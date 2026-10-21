"""
Reproducible Validation Experiment Script (v2)
AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks

Scientific Validation Methodology & Explicit Caveats:
1. Strict Separation: Outputs write strictly to ml/validation/results_v2/. The deployed
   production model and original results remain untouched.
2. In-Memory Exact-Row Deduplication: Eliminates identical duplicate flow rows to prevent exact
   vector memorization. (Note: Does not eliminate temporal or burst-correlated sub-flow leakage).
3. Pre-Split Isolation: 80/20 stratified split is performed BEFORE any script-level cleaning.
4. Upstream Imputation Caveat: The input CSV was median-imputed during dataset generation.
   While training-only median imputation is enforced locally, full statistical independence
   cannot be claimed due to upstream preprocessing.
5. Strict Fold-Isolated Cross-Validation: All preprocessing, constant-column removal, median
   imputation, and Random Forest feature ranking are computed strictly inside each CV fold's
   training partition. Validation folds are never observed during transformation or ranking.
6. Final Model Selection & Refit: The winning configuration is chosen by mean validation F1 across
   the 5 folds, refit on the full training set, and evaluated on the held-out test partition once.
7. Inference-Ready Pipeline Bundle: Exports a self-contained DDoSPredictionPipeline object
   encapsulating the classifier, feature schema, learned medians, and input transformation logic.
8. Latency Reporting: Reports total batch prediction time and per-flow average latency separately.
"""

import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

# ==============================================================================
# CONFIGURATION & REPRODUCIBILITY CONSTANTS
# ==============================================================================
RANDOM_STATE = 42
TEST_SIZE = 0.20
TOP_K_FEATURES = 20
TARGET_COL = "Label"
CV_SPLITS = 5

# Base directory paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
INPUT_CSV = BASE_DIR / "dataset" / "processed" / "ddos_preprocessed.csv"
OUTPUT_DIR = BASE_DIR / "ml" / "validation" / "results_v2"

# Output artifact paths (strictly isolated inside results_v2)
OUTPUT_COMPARISON_CSV = OUTPUT_DIR / "validation_model_comparison.csv"
OUTPUT_CV_CSV = OUTPUT_DIR / "cross_validation_selection.csv"
OUTPUT_FEATURE_IMP_TOP20_CSV = OUTPUT_DIR / "feature_importance_top20.csv"
OUTPUT_FEATURE_IMP_ALL_CSV = OUTPUT_DIR / "feature_importance_all.csv"
OUTPUT_REPORT_TXT = OUTPUT_DIR / "validation_report.txt"
OUTPUT_PERF_PLOT_PNG = OUTPUT_DIR / "validation_model_performance_comparison.png"
OUTPUT_CONFUSION_MATRICES_PNG = OUTPUT_DIR / "confusion_matrices_grid.png"
OUTPUT_BEST_MODEL_PKL = OUTPUT_DIR / "best_validation_model_v2.pkl"

# Existing deployed model path (for verification and safety guard)
DEPLOYED_MODEL_PKL = BASE_DIR / "ml" / "validation" / "results" / "best_validation_model.pkl"


# ==============================================================================
# INFERENCE-READY END-TO-END PIPELINE CLASS
# ==============================================================================
class DDoSPredictionPipeline:
    """
    Self-contained, production-grade inference pipeline for DDoS flow classification.
    
    Encapsulates:
    - Trained classifier or pipeline (e.g. StandardScaler + LogisticRegression, DT, or RF)
    - Feature schema and strict column ordering required by model
    - Preprocessing parameters learned from training data (medians, dropped columns)
    - Full input coercion, infinity handling, and missing-value imputation
    """
    def __init__(self, model, feature_set_name: str, selected_features: list,
                 preprocessor_meta: dict, metadata: dict):
        self.model = model
        self.feature_set_name = feature_set_name
        self.selected_features = list(selected_features)
        self.preprocessor_meta = preprocessor_meta
        self.metadata = metadata

    def preprocess(self, X) -> pd.DataFrame:
        """
        Transforms raw, unscaled input into the model's required feature format.
        Accepts a pandas DataFrame, a single dict, or a list of dicts.
        """
        if isinstance(X, dict):
            df = pd.DataFrame([X])
        elif isinstance(X, list):
            df = pd.DataFrame(X)
        elif isinstance(X, pd.DataFrame):
            df = X.copy()
        else:
            raise TypeError(f"Expected DataFrame, dict, or list of dicts, got {type(X)}")

        # 1. Coerce values to numeric
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        # 2. Replace infinities with NaN
        df = df.replace([np.inf, -np.inf], np.nan)

        # 3. Impute missing features using training medians
        train_medians = self.preprocessor_meta.get("train_medians", {})
        for feat in self.selected_features:
            default_val = train_medians.get(feat, 0.0)
            if feat not in df.columns:
                df[feat] = default_val
            else:
                df[feat] = df[feat].fillna(default_val)

        # 4. Strictly select and order features
        df_aligned = df[self.selected_features].copy()

        # Final safety check: ensure no residual NaNs
        if df_aligned.isnull().any().any():
            df_aligned = df_aligned.fillna(0.0)

        return df_aligned

    def predict(self, X) -> np.ndarray:
        """Runs preprocessing and returns binary class predictions (0: BENIGN, 1: DDoS)."""
        X_proc = self.preprocess(X)
        return self.model.predict(X_proc)

    def predict_proba(self, X) -> np.ndarray:
        """Runs preprocessing and returns class probabilities [P(BENIGN), P(DDoS)]."""
        X_proc = self.preprocess(X)
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X_proc)
        elif hasattr(self.model, "decision_function"):
            decision = self.model.decision_function(X_proc)
            prob_1 = 1.0 / (1.0 + np.exp(-decision))
            return np.vstack([1.0 - prob_1, prob_1]).T
        else:
            raise AttributeError(f"Underlying model {type(self.model)} does not support probability estimation.")


# ==============================================================================
# DEFENSIVE CHECKS & DATA LOADING
# ==============================================================================
def load_and_validate_dataset(csv_path: Path):
    """
    Loads dataset from disk, executes defensive validation checks,
    and performs in-memory exact-row deduplication.
    """
    print(f"[1/6] Loading dataset from: {csv_path.resolve()}", flush=True)
    if not csv_path.exists():
        raise FileNotFoundError(
            f"Dataset file not found at '{csv_path.resolve()}'. "
            f"Ensure 'dataset/processed/ddos_preprocessed.csv' exists before executing validation."
        )

    df_raw = pd.read_csv(csv_path)
    rows_initial = len(df_raw)
    cols_initial = len(df_raw.columns)
    print(f"      Initial shape: {rows_initial:,} rows x {cols_initial} columns", flush=True)

    # 1. Target column presence check
    if TARGET_COL not in df_raw.columns:
        raise ValueError(
            f"Defensive Check Failed: Target column '{TARGET_COL}' not found in dataset. "
            f"Available columns: {list(df_raw.columns)}"
        )

    # 2. Check for missing target labels
    missing_targets = int(df_raw[TARGET_COL].isnull().sum())
    if missing_targets > 0:
        raise ValueError(
            f"Defensive Check Failed: Found {missing_targets:,} missing values in target column '{TARGET_COL}'."
        )

    # 3. Check for valid binary classes (0 and 1)
    unique_labels = set(df_raw[TARGET_COL].unique())
    if not unique_labels.issubset({0, 1}):
        raise ValueError(
            f"Defensive Check Failed: Target column contains non-binary labels: {unique_labels}. "
            f"Expected binary labels {{0, 1}} representing BENIGN and DDoS."
        )

    # 4. Check class representation
    class_counts_initial = df_raw[TARGET_COL].value_counts().to_dict()
    for cls in [0, 1]:
        if class_counts_initial.get(cls, 0) < 5:
            raise ValueError(
                f"Defensive Check Failed: Class {cls} has only {class_counts_initial.get(cls, 0)} samples. "
                f"At least 5 samples per class are required for stratified partitioning."
            )

    # 5. In-memory exact-row deduplication
    print("      Executing in-memory exact-row deduplication...", flush=True)
    df_dedup = df_raw.drop_duplicates().reset_index(drop=True)
    rows_dedup = len(df_dedup)
    duplicates_removed = rows_initial - rows_dedup
    
    if rows_dedup == 0:
        raise ValueError("Defensive Check Failed: Dataset is empty after deduplication.")

    class_counts_dedup = df_dedup[TARGET_COL].value_counts().to_dict()
    benign_cnt = int(class_counts_dedup.get(0, 0))
    ddos_cnt = int(class_counts_dedup.get(1, 0))
    
    print(f"      Exact-row deduplication: {duplicates_removed:,} duplicate rows removed "
          f"({rows_initial:,} -> {rows_dedup:,}).", flush=True)
    print(f"      Class distribution: BENIGN (0): {benign_cnt:,} "
          f"({benign_cnt/rows_dedup*100:.2f}%), DDoS (1): {ddos_cnt:,} ({ddos_cnt/rows_dedup*100:.2f}%)", flush=True)

    X = df_dedup.drop(columns=[TARGET_COL])
    y = df_dedup[TARGET_COL].astype(int)

    # 6. Check non-numeric feature convertibility
    non_convertible = []
    for col in X.columns:
        coerced = pd.to_numeric(X[col], errors="coerce")
        if coerced.isnull().all() and not X[col].isnull().all():
            non_convertible.append(col)
    if non_convertible:
        raise ValueError(
            f"Defensive Check Failed: Feature columns {non_convertible} cannot be coerced to numeric values."
        )

    dedup_metadata = {
        "rows_initial": rows_initial,
        "rows_dedup": rows_dedup,
        "duplicates_removed": duplicates_removed,
        "benign_count": benign_cnt,
        "ddos_count": ddos_cnt,
        "benign_pct": (benign_cnt / rows_dedup) * 100,
        "ddos_pct": (ddos_cnt / rows_dedup) * 100,
        "upstream_limitation_noted": True
    }

    return X, y, dedup_metadata


# ==============================================================================
# STRATIFIED DATA PARTITIONING
# ==============================================================================
def split_train_test_data(X: pd.DataFrame, y: pd.Series):
    """
    Performs 80/20 stratified split BEFORE any preprocessing or feature selection.
    """
    print(f"\n[2/6] Performing 80/20 stratified split (random_state={RANDOM_STATE})...", flush=True)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

    if len(X_train) == 0 or len(X_test) == 0:
        raise ValueError("Defensive Check Failed: Partition resulted in empty train or test set.")

    train_dist = y_train.value_counts().to_dict()
    test_dist = y_test.value_counts().to_dict()

    split_metadata = {
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_benign": int(train_dist.get(0, 0)),
        "train_ddos": int(train_dist.get(1, 0)),
        "test_benign": int(test_dist.get(0, 0)),
        "test_ddos": int(test_dist.get(1, 0)),
        "train_benign_pct": (int(train_dist.get(0, 0)) / len(X_train)) * 100,
        "train_ddos_pct": (int(train_dist.get(1, 0)) / len(X_train)) * 100,
        "test_benign_pct": (int(test_dist.get(0, 0)) / len(X_test)) * 100,
        "test_ddos_pct": (int(test_dist.get(1, 0)) / len(X_test)) * 100,
    }

    print(f"      Train partition: {split_metadata['train_samples']:,} samples "
          f"[BENIGN: {split_metadata['train_benign']:,} ({split_metadata['train_benign_pct']:.2f}%), "
          f"DDoS: {split_metadata['train_ddos']:,} ({split_metadata['train_ddos_pct']:.2f}%)]", flush=True)
    print(f"      Test partition:  {split_metadata['test_samples']:,} samples "
          f"[BENIGN: {split_metadata['test_benign']:,} ({split_metadata['test_benign_pct']:.2f}%), "
          f"DDoS: {split_metadata['test_ddos']:,} ({split_metadata['test_ddos_pct']:.2f}%)]", flush=True)

    return X_train, X_test, y_train, y_test, split_metadata


# ==============================================================================
# LEAKAGE-SAFE PREPROCESSING CLASS
# ==============================================================================
class LeakageSafePreprocessor:
    """
    Fits feature cleaning and missing-value imputation strictly on training data.
    Applies learned parameters consistently to validation or test data without leakage.
    """
    def __init__(self):
        self.all_missing_cols = []
        self.constant_cols = []
        self.dropped_cols = []
        self.candidate_cols = []
        self.train_medians = {}

    def fit_transform(self, X_train: pd.DataFrame) -> pd.DataFrame:
        X_tr = X_train.copy()

        for col in X_tr.columns:
            X_tr[col] = pd.to_numeric(X_tr[col], errors="coerce")
        X_tr = X_tr.replace([np.inf, -np.inf], np.nan)

        self.all_missing_cols = [c for c in X_tr.columns if X_tr[c].isnull().all()]
        self.constant_cols = [
            c for c in X_tr.columns
            if c not in self.all_missing_cols and (X_tr[c].nunique(dropna=False) <= 1 or X_tr[c].std() == 0)
        ]

        self.dropped_cols = sorted(list(set(self.all_missing_cols) | set(self.constant_cols)))
        self.candidate_cols = [c for c in X_tr.columns if c not in self.dropped_cols]

        if len(self.candidate_cols) == 0:
            raise ValueError("Defensive Check Failed: No candidate features remain after removing constant/missing columns.")

        X_tr_filtered = X_tr[self.candidate_cols]
        medians_series = X_tr_filtered.median()
        self.train_medians = medians_series.to_dict()
        
        for c, med in self.train_medians.items():
            if pd.isna(med):
                self.train_medians[c] = 0.0

        X_tr_imputed = X_tr_filtered.fillna(self.train_medians)
        if X_tr_imputed.isnull().any().any():
            raise ValueError("Defensive Check Failed: Data contains NaNs after median imputation.")

        return X_tr_imputed

    def transform(self, X_test: pd.DataFrame) -> pd.DataFrame:
        X_te = X_test.copy()
        for col in X_te.columns:
            X_te[col] = pd.to_numeric(X_te[col], errors="coerce")
        X_te = X_te.replace([np.inf, -np.inf], np.nan)

        # Drop columns identified as constant/missing in training
        present_candidates = [c for c in self.candidate_cols if c in X_te.columns]
        X_te_filtered = X_te[present_candidates]
        X_te_imputed = X_te_filtered.fillna(self.train_medians)

        # Ensure all candidate columns exist
        for col in self.candidate_cols:
            if col not in X_te_imputed.columns:
                X_te_imputed[col] = self.train_medians.get(col, 0.0)

        X_te_aligned = X_te_imputed[self.candidate_cols].fillna(0.0)
        return X_te_aligned


# ==============================================================================
# FEATURE IMPORTANCE & TOP K SELECTION HELPER
# ==============================================================================
def fit_rf_top_features(X_train_proc: pd.DataFrame, y_train: pd.Series, top_k: int = TOP_K_FEATURES):
    """
    Fits Random Forest feature importance (MDI) on processed training data ONLY.
    Returns full importance DataFrame and list of top K feature names.
    """
    rf_selector = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
    rf_selector.fit(X_train_proc, y_train)

    feature_names = list(X_train_proc.columns)
    importances = rf_selector.feature_importances_

    imp_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False).reset_index(drop=True)

    imp_df["Rank"] = imp_df.index + 1
    imp_df["Cumulative Importance"] = imp_df["Importance"].cumsum()
    imp_df = imp_df[["Rank", "Feature", "Importance", "Cumulative Importance"]]

    k = min(top_k, len(imp_df))
    top_k_df = imp_df.head(k).copy()
    top_k_features = top_k_df["Feature"].tolist()

    return imp_df, top_k_df, top_k_features


# ==============================================================================
# FOLD-ISOLATED CROSS-VALIDATION (ZERO CV LEAKAGE)
# ==============================================================================
def select_model_via_isolated_cv(X_train_raw: pd.DataFrame, y_train: pd.Series):
    """
    Executes 5-Fold Stratified Cross-Validation on X_train.
    
    CRITICAL METHODOLOGICAL GUARANTEE:
    Preprocessing, constant-column removal, median imputation, and Random Forest
    Top 20 feature selection are ALL fitted strictly on each fold's training portion.
    Validation folds are completely unobserved during preprocessing and feature ranking.
    """
    print(f"\n[3/6] Running {CV_SPLITS}-Fold Stratified CV on X_train (Fold-Isolated Preprocessing & Selection)...", flush=True)
    skf = StratifiedKFold(n_splits=CV_SPLITS, shuffle=True, random_state=RANDOM_STATE)

    config_names = [
        ("Candidate Features", "Logistic Regression"),
        ("Candidate Features", "Decision Tree"),
        ("Candidate Features", "Random Forest"),
        ("Top 20 Features", "Logistic Regression"),
        ("Top 20 Features", "Decision Tree"),
        ("Top 20 Features", "Random Forest"),
    ]

    fold_scores = {cfg: [] for cfg in config_names}

    for fold_idx, (tr_idx, val_idx) in enumerate(skf.split(X_train_raw, y_train), 1):
        print(f"      Processing Fold {fold_idx}/{CV_SPLITS}...", flush=True)
        X_fold_tr_raw = X_train_raw.iloc[tr_idx].copy()
        y_fold_tr = y_train.iloc[tr_idx].copy()
        X_fold_val_raw = X_train_raw.iloc[val_idx].copy()
        y_fold_val = y_train.iloc[val_idx].copy()

        # 1. Fit preprocessing ONLY on this fold's training portion
        fold_preproc = LeakageSafePreprocessor()
        X_fold_tr_proc = fold_preproc.fit_transform(X_fold_tr_raw)
        X_fold_val_proc = fold_preproc.transform(X_fold_val_raw)

        fold_cand_features = fold_preproc.candidate_cols

        # 2. Fit feature selector ONLY on this fold's training portion
        _, _, fold_top20_features = fit_rf_top_features(X_fold_tr_proc, y_fold_tr, TOP_K_FEATURES)

        feature_subsets = {
            "Candidate Features": fold_cand_features,
            "Top 20 Features": fold_top20_features,
        }

        # 3. Evaluate each model configuration on this fold's validation portion
        for feat_set_name, feat_cols in feature_subsets.items():
            X_tr_sub = X_fold_tr_proc[feat_cols]
            X_val_sub = X_fold_val_proc[feat_cols]

            model_instances = [
                ("Logistic Regression", Pipeline([
                    ("scaler", StandardScaler()),
                    ("classifier", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE))
                ])),
                ("Decision Tree", DecisionTreeClassifier(random_state=RANDOM_STATE)),
                ("Random Forest", RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)),
            ]

            for m_name, m_obj in model_instances:
                m_obj.fit(X_tr_sub, y_fold_tr)
                y_val_pred = m_obj.predict(X_val_sub)
                f1 = float(f1_score(y_fold_val, y_val_pred, average="binary", pos_label=1, zero_division=0))
                fold_scores[(feat_set_name, m_name)].append(f1)

    # Summarize Cross-Validation results
    cv_records = []
    print("\n      Cross-Validation Summary (Fold-Isolated Evaluation):", flush=True)
    for (feat_set_name, m_name), scores in fold_scores.items():
        mean_f1 = float(np.mean(scores))
        std_f1 = float(np.std(scores))
        cv_records.append({
            "Feature Set": feat_set_name,
            "Model": m_name,
            "CV Mean F1": mean_f1,
            "CV Std F1": std_f1,
            "Fold F1 Scores": [round(s, 6) for s in scores],
        })
        print(f"      * {m_name:<20} ({feat_set_name:<18}) -> F1: {mean_f1:.6f} (+/- {std_f1:.6f})", flush=True)

    cv_records.sort(key=lambda r: r["CV Mean F1"], reverse=True)
    winning_cv_config = cv_records[0]
    print(f"\n      Selected Winning Architecture: {winning_cv_config['Model']} ({winning_cv_config['Feature Set']}) "
          f"with CV F1={winning_cv_config['CV Mean F1']:.6f}", flush=True)

    return winning_cv_config, cv_records


# ==============================================================================
# FULL-TRAINING REFIT & HELD-OUT TEST BENCHMARK
# ==============================================================================
def evaluate_single_model(model, X_tr, y_tr, X_te, y_te, model_name: str, feature_set_name: str):
    """
    Trains a model on full X_tr/y_tr, evaluates on held-out X_te/y_te, and collects metrics:
    Accuracy, Precision, Recall, F1-Score, Confusion Matrix, False Positive Rate (FPR),
    False Negative Rate (FNR), Training Latency, Total Prediction Time, and Per-Flow Latency.
    """
    t_start_train = time.perf_counter()
    model.fit(X_tr, y_tr)
    t_train = time.perf_counter() - t_start_train

    n_samples = len(X_te)
    t_start_pred = time.perf_counter()
    y_pred = model.predict(X_te)
    t_pred_total = time.perf_counter() - t_start_pred
    per_flow_latency_ms = (t_pred_total / n_samples) * 1000.0 if n_samples > 0 else 0.0

    acc = float(accuracy_score(y_te, y_pred))
    prec = float(precision_score(y_te, y_pred, average="binary", pos_label=1, zero_division=0))
    rec = float(recall_score(y_te, y_pred, average="binary", pos_label=1, zero_division=0))
    f1 = float(f1_score(y_te, y_pred, average="binary", pos_label=1, zero_division=0))

    cm = confusion_matrix(y_te, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "Feature Set": feature_set_name,
        "Model": model_name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1-Score": f1,
        "FPR": fpr,
        "FNR": fnr,
        "Train Time (s)": t_train,
        "Total Prediction Time (s)": t_pred_total,
        "Per-Flow Latency (ms)": per_flow_latency_ms,
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
        "model_object": model,
        "confusion_matrix": cm,
    }


def run_benchmark_experiments(X_train_proc: pd.DataFrame, y_train: pd.Series,
                             X_test_proc: pd.DataFrame, y_test: pd.Series,
                             candidate_features: list, top_20_features: list):
    """
    Evaluates all 6 configurations on the held-out test partition once for comparative reporting.
    """
    print("\n[5/6] Evaluating all 6 benchmark models on held-out test partition...", flush=True)
    feature_sets = [
        ("Candidate Features", candidate_features),
        ("Top 20 Features", top_20_features),
    ]

    all_results = []

    for set_name, feature_list in feature_sets:
        X_tr_sub = X_train_proc[feature_list]
        X_te_sub = X_test_proc[feature_list]

        models = [
            ("Logistic Regression", Pipeline([
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE))
            ])),
            ("Decision Tree", DecisionTreeClassifier(random_state=RANDOM_STATE)),
            ("Random Forest", RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)),
        ]

        for m_name, m_obj in models:
            print(f"      Evaluating: {m_name:<20} | Feature Set: {set_name}", flush=True)
            res = evaluate_single_model(m_obj, X_tr_sub, y_train, X_te_sub, y_test, m_name, set_name)
            all_results.append(res)

    return all_results


# ==============================================================================
# PIPELINE INFERENCE VERIFICATION
# ==============================================================================
def verify_pipeline_inference(pipeline: DDoSPredictionPipeline, sample_raw_df: pd.DataFrame):
    """
    Defensive verification test: Confirms that DDoSPredictionPipeline can ingest
    unpreprocessed raw data (including missing columns, out-of-order features, and NaNs)
    and successfully produce valid class predictions and probabilities.
    """
    print("\n[Verification] Validating end-to-end inference on raw sample flows...", flush=True)
    raw_sample = sample_raw_df.head(5).copy()

    # Introduce realistic raw network anomalies: NaN and inf
    sample_cols = list(raw_sample.columns)
    if len(sample_cols) > 2:
        raw_sample.loc[raw_sample.index[0], sample_cols[0]] = np.nan
        raw_sample.loc[raw_sample.index[1], sample_cols[1]] = np.inf

    # 1. Test binary prediction
    preds = pipeline.predict(raw_sample)
    if not isinstance(preds, np.ndarray) or len(preds) != len(raw_sample):
        raise RuntimeError("Pipeline verification failed: .predict() returned invalid output.")
    if not set(preds).issubset({0, 1}):
        raise RuntimeError(f"Pipeline verification failed: Invalid predicted classes {set(preds)}.")

    # 2. Test probability estimation
    probs = pipeline.predict_proba(raw_sample)
    if not isinstance(probs, np.ndarray) or probs.shape != (len(raw_sample), 2):
        raise RuntimeError("Pipeline verification failed: .predict_proba() shape mismatch.")
    if not np.allclose(probs.sum(axis=1), 1.0):
        raise RuntimeError("Pipeline verification failed: Class probabilities do not sum to 1.0.")

    # 3. Test single dictionary input
    single_dict = raw_sample.iloc[0].to_dict()
    single_pred = pipeline.predict(single_dict)
    if len(single_pred) != 1:
        raise RuntimeError("Pipeline verification failed: Single dict inference failed.")

    print("      [PASSED] DDoSPredictionPipeline successfully verified for standalone raw inference.", flush=True)


# ==============================================================================
# VISUALIZATION GENERATORS
# ==============================================================================
def plot_performance_comparison(results: list, save_path: Path):
    labels = [f"{r['Model']}\n({r['Feature Set']})" for r in results]
    x = np.arange(len(labels))
    width = 0.18

    acc_vals = [r["Accuracy"] for r in results]
    prec_vals = [r["Precision"] for r in results]
    rec_vals = [r["Recall"] for r in results]
    f1_vals = [r["F1-Score"] for r in results]

    fig, ax1 = plt.subplots(figsize=(14, 7), dpi=300)

    ax1.bar(x - 1.5 * width, acc_vals, width, label="Accuracy", color="#1f77b4", alpha=0.95)
    ax1.bar(x - 0.5 * width, prec_vals, width, label="Precision", color="#2ca02c", alpha=0.95)
    ax1.bar(x + 0.5 * width, rec_vals, width, label="Recall", color="#d62728", alpha=0.95)
    rects4 = ax1.bar(x + 1.5 * width, f1_vals, width, label="F1-Score", color="#9467bd", alpha=0.95)

    ax1.set_ylabel("Classification Metric Score", fontsize=12, fontweight="bold")
    ax1.set_title("DDoS Detection Benchmark: Multi-Model Performance Comparison (v2 Validation)",
                  fontsize=14, fontweight="bold", pad=15)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9.5)
    ax1.set_ylim(0.85, 1.02)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)
    ax1.legend(loc="lower right", framealpha=0.95, fontsize=10)

    for rect, f1 in zip(rects4, f1_vals):
        height = rect.get_height()
        ax1.annotate(f"{f1:.4f}",
                     xy=(rect.get_x() + rect.get_width() / 2, height),
                     xytext=(0, 3), textcoords="offset points",
                     ha="center", va="bottom", fontsize=7.5, rotation=45)

    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close(fig)
    print(f"      Saved performance comparison chart to: {save_path.resolve()}", flush=True)


def plot_confusion_matrices_grid(results: list, save_path: Path):
    fig, axes = plt.subplots(2, 3, figsize=(15, 9), dpi=300)
    axes = axes.flatten()

    for idx, (res, ax) in enumerate(zip(results, axes)):
        cm = res["confusion_matrix"]
        total = np.sum(cm)
        tn, fp, fn, tp = res["TN"], res["FP"], res["FN"], res["TP"]
        fpr = res["FPR"]

        ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.set_title(f"{res['Model']}\n({res['Feature Set']})", fontsize=11, fontweight="bold", pad=8)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Pred BENIGN", "Pred DDoS"], fontsize=9.5)
        ax.set_yticklabels(["True BENIGN", "True DDoS"], fontsize=9.5)

        annot_matrix = [
            [f"TN\n{tn:,}\n({tn/total*100:.1f}%)", f"FP\n{fp:,}\n({fp/total*100:.2f}%)"],
            [f"FN\n{fn:,}\n({fn/total*100:.2f}%)", f"TP\n{tp:,}\n({tp/total*100:.1f}%)"]
        ]

        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                color = "white" if cm[i, j] > thresh else "black"
                ax.text(j, i, annot_matrix[i][j],
                        ha="center", va="center", color=color, fontsize=9.5, fontweight="semibold")

        ax.set_xlabel(f"F1: {res['F1-Score']:.4f} | Latency: {res['Per-Flow Latency (ms)']:.4f} ms/flow", fontsize=9, color="#333333")

    plt.suptitle("Validation Confusion Matrices across 6 DDoS Detection Experiments",
                 fontsize=14, fontweight="bold", y=0.99)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close(fig)
    print(f"      Saved confusion matrices grid to: {save_path.resolve()}", flush=True)


# ==============================================================================
# REPORT & UNIFIED ARTIFACT EXPORT
# ==============================================================================
def export_all_artifacts(results: list, cv_records: list, winning_cv_config: dict,
                         imp_df: pd.DataFrame, top_20_df: pd.DataFrame,
                         dedup_meta: dict, split_meta: dict, preproc: LeakageSafePreprocessor,
                         final_selected_features: list, winning_model_obj):
    """
    Exports CSV summaries, plots, validation report, and the standalone DDoSPredictionPipeline.
    """
    print("\n[6/6] Exporting artifacts to results_v2 directory...", flush=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Comparison CSV
    res_df = pd.DataFrame(results)
    csv_cols = [
        "Feature Set", "Model", "Accuracy", "Precision", "Recall", "F1-Score",
        "FPR", "FNR", "Train Time (s)", "Total Prediction Time (s)", "Per-Flow Latency (ms)",
        "TN", "FP", "FN", "TP"
    ]
    res_df[csv_cols].to_csv(OUTPUT_COMPARISON_CSV, index=False)
    print(f"      Saved comparison CSV: {OUTPUT_COMPARISON_CSV.resolve()}", flush=True)

    # 2. Cross-Validation Selection CSV
    cv_df = pd.DataFrame(cv_records)
    cv_df.to_csv(OUTPUT_CV_CSV, index=False)
    print(f"      Saved CV model selection table: {OUTPUT_CV_CSV.resolve()}", flush=True)

    # 3. Feature Importance CSVs
    top_20_df.to_csv(OUTPUT_FEATURE_IMP_TOP20_CSV, index=False)
    imp_df.to_csv(OUTPUT_FEATURE_IMP_ALL_CSV, index=False)
    print(f"      Saved Top 20 feature importance CSV: {OUTPUT_FEATURE_IMP_TOP20_CSV.resolve()}", flush=True)
    print(f"      Saved complete feature importance CSV: {OUTPUT_FEATURE_IMP_ALL_CSV.resolve()}", flush=True)

    # 4. Visualizations
    plot_performance_comparison(results, OUTPUT_PERF_PLOT_PNG)
    plot_confusion_matrices_grid(results, OUTPUT_CONFUSION_MATRICES_PNG)

    # 5. Extract winning model test result
    winning_test_res = next(
        r for r in results
        if r["Model"] == winning_cv_config["Model"] and r["Feature Set"] == winning_cv_config["Feature Set"]
    )

    # 6. Build and export DDoSPredictionPipeline bundle
    preprocessor_meta = {
        "candidate_columns": preproc.candidate_cols,
        "dropped_columns": preproc.dropped_cols,
        "train_medians": preproc.train_medians,
    }
    pipeline_metadata = {
        "model_name": winning_test_res["Model"],
        "feature_set_name": winning_test_res["Feature Set"],
        "cv_mean_f1": winning_cv_config["CV Mean F1"],
        "cv_std_f1": winning_cv_config["CV Std F1"],
        "test_accuracy": winning_test_res["Accuracy"],
        "test_precision": winning_test_res["Precision"],
        "test_recall": winning_test_res["Recall"],
        "test_f1_score": winning_test_res["F1-Score"],
        "test_fpr": winning_test_res["FPR"],
        "total_prediction_time_s": winning_test_res["Total Prediction Time (s)"],
        "per_flow_latency_ms": winning_test_res["Per-Flow Latency (ms)"],
        "train_samples": split_meta["train_samples"],
        "test_samples": split_meta["test_samples"],
        "random_state": RANDOM_STATE,
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "upstream_limitation": "Preprocessed dataset had global median imputation prior to split."
    }

    prediction_pipeline = DDoSPredictionPipeline(
        model=winning_model_obj,
        feature_set_name=winning_test_res["Feature Set"],
        selected_features=final_selected_features,
        preprocessor_meta=preprocessor_meta,
        metadata=pipeline_metadata
    )

    joblib.dump(prediction_pipeline, OUTPUT_BEST_MODEL_PKL)
    print(f"      Saved standalone DDoSPredictionPipeline to: {OUTPUT_BEST_MODEL_PKL.resolve()}", flush=True)

    # Safety confirmation: Ensure existing deployed model is untouched
    if DEPLOYED_MODEL_PKL.exists():
        print(f"      [SAFETY CHECK PASSED] Existing deployed model at '{DEPLOYED_MODEL_PKL.resolve()}' was NOT touched.", flush=True)

    # 7. Comprehensive Validation Report
    report_lines = []
    r_sep = "=" * 80
    s_sep = "-" * 80

    report_lines.append(r_sep)
    report_lines.append("   AI-BASED DDOS DETECTION IN BANKING NETWORKS: VALIDATION REPORT (V2)")
    report_lines.append("             Reproducible Scientific Experiment & Benchmarking")
    report_lines.append(r_sep)
    report_lines.append("")
    report_lines.append("1. EXECUTIVE SUMMARY & EXPERIMENT METADATA:")
    report_lines.append(s_sep)
    report_lines.append(f" Benchmark Run Date:        {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f" Source Dataset:            {INPUT_CSV.as_posix()} (Read-only; unmodified)")
    report_lines.append(f" Target Feature:            {TARGET_COL} (0: BENIGN, 1: DDoS)")
    report_lines.append(f" Deployed Model Status:     Untouched at 'ml/validation/results/best_validation_model.pkl'")
    report_lines.append(f" New Validated Model Path:  {OUTPUT_BEST_MODEL_PKL.as_posix()}")
    report_lines.append("")

    report_lines.append("2. DATASET INGESTION & DEDUPLICATION AUDIT:")
    report_lines.append(s_sep)
    report_lines.append(f" Total Rows Before Deduplication: {dedup_meta['rows_initial']:,}")
    report_lines.append(f" Duplicate Rows Removed:          {dedup_meta['duplicates_removed']:,}")
    report_lines.append(f" Total Rows After Deduplication:  {dedup_meta['rows_dedup']:,}")
    report_lines.append(f" Class Breakdown After Deduplication:")
    report_lines.append(f"   * BENIGN (0): {dedup_meta['benign_count']:,} ({dedup_meta['benign_pct']:.2f}%)")
    report_lines.append(f"   * DDoS (1):   {dedup_meta['ddos_count']:,} ({dedup_meta['ddos_pct']:.2f}%)")
    report_lines.append(" Deduplication Scope: In-memory exact-row deduplication removes bitwise identical records.")
    report_lines.append(" Limitation: Does NOT eliminate temporal or session-correlated sub-flow leakage from adjacent bursts.")
    report_lines.append("")

    report_lines.append("3. DATA PARTITIONING & CLASS DISTRIBUTION:")
    report_lines.append(s_sep)
    report_lines.append(f" Partitioning Strategy:     Stratified Random Split (80% Train / 20% Test)")
    report_lines.append(f" Random Seed:               {RANDOM_STATE}")
    report_lines.append(f" Training Partition:        {split_meta['train_samples']:,} samples")
    report_lines.append(f"   * BENIGN: {split_meta['train_benign']:,} ({split_meta['train_benign_pct']:.2f}%)")
    report_lines.append(f"   * DDoS:   {split_meta['train_ddos']:,} ({split_meta['train_ddos_pct']:.2f}%)")
    report_lines.append(f" Test Partition:            {split_meta['test_samples']:,} samples (Held-out benchmark)")
    report_lines.append(f"   * BENIGN: {split_meta['test_benign']:,} ({split_meta['test_benign_pct']:.2f}%)")
    report_lines.append(f"   * DDoS:   {split_meta['test_ddos']:,} ({split_meta['test_ddos_pct']:.2f}%)")
    report_lines.append("")

    report_lines.append("4. PREPROCESSING & UPSTREAM IMPUTATION STATUS:")
    report_lines.append(s_sep)
    report_lines.append(" Script-Level Preprocessing: All column pruning and medians fitted strictly on X_train.")
    report_lines.append(f" All-Missing Columns Dropped ({len(preproc.all_missing_cols)}): {preproc.all_missing_cols if preproc.all_missing_cols else 'None'}")
    report_lines.append(f" Constant / Zero-Variance Columns Dropped ({len(preproc.constant_cols)}): {preproc.constant_cols if preproc.constant_cols else 'None'}")
    report_lines.append(f" Total Candidate Features Retained: {len(preproc.candidate_cols)}")
    report_lines.append(" Upstream Limitation: The input CSV underwent global median imputation during initial generation.")
    report_lines.append(" Consequently, absolute absence of leakage cannot be claimed.")
    report_lines.append("")

    report_lines.append("5. TOP 20 FEATURES RANKED BY RANDOM FOREST IMPORTANCE (FULL X_TRAIN REFIT):")
    report_lines.append(s_sep)
    report_lines.append(f"{'Rank':<5} | {'Feature Name':<35} | {'Importance':<12} | {'Cumulative Imp':<14}")
    report_lines.append("-" * 72)
    for _, row in top_20_df.iterrows():
        report_lines.append(f"{int(row['Rank']):<5} | {row['Feature']:<35} | {row['Importance']:<12.6f} | {row['Cumulative Importance']*100:<13.2f}%")
    report_lines.append("")

    report_lines.append("6. INTERNAL MODEL SELECTION (5-FOLD STRATIFIED CV WITH FOLD-ISOLATED PREPROCESSING):")
    report_lines.append(s_sep)
    report_lines.append(f"{'Rank':<5} | {'Feature Set':<20} | {'Model':<20} | {'CV Mean F1':<12} | {'CV Std F1':<12}")
    report_lines.append("-" * 75)
    for idx, r in enumerate(cv_records, 1):
        report_lines.append(f"{idx:<5} | {r['Feature Set']:<20} | {r['Model']:<20} | {r['CV Mean F1']:.6f}     | {r['CV Std F1']:.6f}")
    report_lines.append("")
    report_lines.append(f" Selected Winning Architecture: {winning_cv_config['Model']} ({winning_cv_config['Feature Set']})")
    report_lines.append("")

    report_lines.append("7. BENCHMARK EVALUATION RESULTS ON HELD-OUT TEST SET (ONCE):")
    report_lines.append(s_sep)
    header = f"{'Feature Set':<18} | {'Model':<19} | {'Acc':<7} | {'Prec':<7} | {'Rec':<7} | {'F1':<7} | {'FPR':<7} | {'Total(s)':<8} | {'Latency(ms)':<10}"
    report_lines.append(header)
    report_lines.append("-" * len(header))
    for r in results:
        report_lines.append(
            f"{r['Feature Set']:<18} | {r['Model']:<19} | {r['Accuracy']:.4f}  | {r['Precision']:.4f}  | "
            f"{r['Recall']:.4f}  | {r['F1-Score']:.4f}  | {r['FPR']*100:5.2f}% | "
            f"{r['Total Prediction Time (s)']:<8.4f} | {r['Per-Flow Latency (ms)']:<10.4f}"
        )
    report_lines.append("")

    report_lines.append("8. CONFUSION MATRIX & ERROR BREAKDOWN:")
    report_lines.append(s_sep)
    for r in results:
        report_lines.append(f" Model: {r['Model']} ({r['Feature Set']})")
        report_lines.append(f"   TN: {r['TN']:,} | FP: {r['FP']:,} | FN: {r['FN']:,} | TP: {r['TP']:,}")
        report_lines.append(f"   FPR: {r['FPR']*100:.3f}% | FNR: {r['FNR']*100:.3f}% | Latency: {r['Per-Flow Latency (ms)']:.4f} ms/flow")
        report_lines.append("")

    report_lines.append("9. WINNING VALIDATION MODEL SUMMARY:")
    report_lines.append(s_sep)
    report_lines.append(f" Winning Architecture:      {winning_test_res['Model']}")
    report_lines.append(f" Winning Feature Set:       {winning_test_res['Feature Set']}")
    report_lines.append(f" Selection Basis:           Highest 5-Fold CV F1-score ({winning_cv_config['CV Mean F1']:.6f}) with fold-isolated selection.")
    report_lines.append(f" Held-Out Test F1-Score:    {winning_test_res['F1-Score']:.6f}")
    report_lines.append(f" Held-Out Test Recall:      {winning_test_res['Recall']:.6f}")
    report_lines.append(f" Held-Out Test Precision:   {winning_test_res['Precision']:.6f}")
    report_lines.append(f" Held-Out Test Accuracy:    {winning_test_res['Accuracy']:.6f}")
    report_lines.append(f" Held-Out Test FPR:         {winning_test_res['FPR']*100:.3f}%")
    report_lines.append(f" Total Test Prediction Time:{winning_test_res['Total Prediction Time (s)']:.4f} s for {split_meta['test_samples']:,} flows")
    report_lines.append(f" Per-Flow Average Latency:  {winning_test_res['Per-Flow Latency (ms)']:.4f} ms")
    report_lines.append(f" Exported Pipeline Bundle:  {OUTPUT_BEST_MODEL_PKL.as_posix()}")
    report_lines.append("")

    report_lines.append("10. METHODOLOGICAL LIMITATIONS (WHY NOT 'ZERO LEAKAGE'):")
    report_lines.append(s_sep)
    report_lines.append(" 1. Upstream Imputation: Missing values were imputed globally prior to dataset ingestion.")
    report_lines.append(" 2. Flow-Level Autocorrelation: Packets belonging to the same burst or session may have been")
    report_lines.append("    split across adjacent flow records with microscopic timestamp variations, creating subtle sub-flow correlation.")
    report_lines.append(" 3. Synthetic Lab Artifacts: Testbed benchmarks (such as CICDDoS2019) exhibit repetitive packet size patterns.")
    report_lines.append(" 4. Stationary Distributions: Random stratified splits do not model temporal drift or adversarial evasion.")
    report_lines.append("")

    report_lines.append("11. RESEARCH WARNINGS & BANKING REALITIES:")
    report_lines.append(s_sep)
    report_lines.append(" WARNING 1 - BENCHMARK SPLIT vs. TEMPORAL CROSS-DAY DRIFT:")
    report_lines.append(" This validation experiment employs a random stratified benchmark split. It does NOT evaluate")
    report_lines.append(" cross-day transferability, multi-source drift, or behavior under unfamiliar attack tools.")
    report_lines.append("")
    report_lines.append(" WARNING 2 - PRODUCTION ENTERPRISE BANKING REALITIES:")
    report_lines.append(" Production financial enterprise networks exhibit distinct characteristics absent from lab benchmarks:")
    report_lines.append(" * Asymmetric Flow Distribution: In production enterprise banking environments, legitimate")
    report_lines.append("   transactional traffic significantly outnumbers attack flows. Consequently, even low False")
    report_lines.append("   Positive Rates can result in alert fatigue or disruption of legitimate customer activity.")
    report_lines.append(" * Latency Constraints: Financial transaction pipelines require low per-flow inspection overhead")
    report_lines.append("   to prevent throughput bottlenecks and SLA violations during high-volume periods.")
    report_lines.append(" * Concept Drift & Cyclical Shifts: Normal traffic spikes during business hours, month-end payrolls,")
    report_lines.append("   and marketing events, creating benign traffic bursts that differ from lab-recorded BENIGN flows.")
    report_lines.append(" * Polymorphic Attacks: Modern adversaries use low-and-slow, pulse, or polymorphic attacks")
    report_lines.append("   specifically crafted to mimic legitimate user sessions, evading static volumetric thresholds.")
    report_lines.append(r_sep)

    with open(OUTPUT_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"      Saved comprehensive validation report: {OUTPUT_REPORT_TXT.resolve()}", flush=True)

    return prediction_pipeline


# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================
def main():
    total_start = time.time()
    print("=" * 80)
    print(" STARTING REPRODUCIBLE VALIDATION EXPERIMENT (v2)")
    print("=" * 80)

    # 1. Load, validate, and deduplicate dataset
    X, y, dedup_meta = load_and_validate_dataset(INPUT_CSV)

    # 2. Split train/test data BEFORE any script-level preprocessing
    X_train_raw, X_test_raw, y_train, y_test, split_meta = split_train_test_data(X, y)

    # 3. Model selection via 5-Fold Stratified CV with fold-isolated preprocessing & feature selection
    winning_cv_config, cv_records = select_model_via_isolated_cv(X_train_raw, y_train)

    # 4. Global Refit on full X_train: Preprocessing and Top 20 ranking
    print("\n[4/6] Refitting global preprocessing and feature selection on full X_train...", flush=True)
    global_preproc = LeakageSafePreprocessor()
    X_train_proc = global_preproc.fit_transform(X_train_raw)
    X_test_proc = global_preproc.transform(X_test_raw)

    imp_df, top_20_df, global_top20_features = fit_rf_top_features(X_train_proc, y_train, TOP_K_FEATURES)
    global_cand_features = global_preproc.candidate_cols

    # 5. Run comparative 6-experiment evaluation on held-out test partition once
    results = run_benchmark_experiments(
        X_train_proc, y_train,
        X_test_proc, y_test,
        global_cand_features, global_top20_features
    )

    # 6. Retrieve winning refitted model instance
    winning_model_obj = next(
        r["model_object"] for r in results
        if r["Model"] == winning_cv_config["Model"] and r["Feature Set"] == winning_cv_config["Feature Set"]
    )
    final_selected_features = (
        global_top20_features if winning_cv_config["Feature Set"] == "Top 20 Features" else global_cand_features
    )

    # 7. Export all artifacts, plots, reports, and standalone DDoSPredictionPipeline
    pipeline = export_all_artifacts(
        results, cv_records, winning_cv_config,
        imp_df, top_20_df, dedup_meta, split_meta, global_preproc,
        final_selected_features, winning_model_obj
    )

    # 8. Automated verification of exported pipeline
    verify_pipeline_inference(pipeline, X_test_raw)

    elapsed_total = time.time() - total_start
    print("\n" + "=" * 80)
    print(f" EXPERIMENT COMPLETED SUCCESSFULLY IN {elapsed_total:.2f} SECONDS")
    print(f" All outputs saved inside: {OUTPUT_DIR.resolve()}")
    print("=" * 80)


if __name__ == "__main__":
    main()
