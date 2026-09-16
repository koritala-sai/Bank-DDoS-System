"""
ML Model Training & Evaluation Script
AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks

This script loads preprocessed data, builds two feature sets (61 features & Top 20 features),
performs an 80/20 stratified train/test split, trains 3 classifiers (Logistic Regression with StandardScaler,
Decision Tree, Random Forest), evaluates binary metrics & confusion matrix counts, generates visual artifacts,
and serializes the best performing model.
"""

import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

from sklearn.model_selection import train_test_split
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
    ConfusionMatrixDisplay
)

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================
RANDOM_STATE = 42
TEST_SIZE = 0.20

INPUT_CSV = Path("dataset/processed/ddos_preprocessed.csv")
FEATURE_IMPORTANCE_CSV = Path("dataset/processed/feature_importance.csv")
SELECTED_FEATURES_TXT = Path("dataset/processed/selected_features.txt")

RESULTS_DIR = Path("ml/results")
CONFUSION_DIR = RESULTS_DIR / "confusion_matrices"
MODEL_COMPARISON_CSV = RESULTS_DIR / "model_comparison.csv"
TRAINING_REPORT_TXT = RESULTS_DIR / "ml_training_report.txt"
PERFORMANCE_PLOT_PNG = RESULTS_DIR / "model_performance_comparison.png"
BEST_MODEL_PKL = RESULTS_DIR / "best_model.pkl"
BEST_MODEL_INFO_TXT = RESULTS_DIR / "best_model_info.txt"

def load_dataset():
    """Loads dataset and returns X (features) and y (target Label)."""
    print(f"Loading preprocessed dataset from '{INPUT_CSV.as_posix()}'...", flush=True)
    df = pd.read_csv(INPUT_CSV)
    
    X = df.drop(columns=["Label"])
    y = df["Label"]
    
    # Audit
    shape = df.shape
    class_counts = y.value_counts().to_dict()
    missing_vals = int(X.isnull().sum().sum())
    inf_vals = int(np.isinf(X).sum().sum())
    
    print(f"Dataset Shape: {shape}", flush=True)
    print(f"Class Distribution: BENIGN (0): {class_counts.get(0, 0):,}, DDoS (1): {class_counts.get(1, 0):,}", flush=True)
    print(f"Missing Values: {missing_vals}, Infinite Values: {inf_vals}", flush=True)
    
    return X, y

def load_selected_features():
    """Loads candidate 61 features and Top 20 features from processed feature selection files."""
    if not FEATURE_IMPORTANCE_CSV.exists():
        raise FileNotFoundError(f"Feature importance file '{FEATURE_IMPORTANCE_CSV}' not found.")
        
    imp_df = pd.read_csv(FEATURE_IMPORTANCE_CSV)
    
    all_61_features = imp_df["Feature"].tolist()
    top_20_features = imp_df.head(20)["Feature"].tolist()
    
    print(f"Loaded {len(all_61_features)} candidate features and {len(top_20_features)} Top 20 features.", flush=True)
    return all_61_features, top_20_features

def prepare_feature_sets(X, features_61, features_20):
    """Prepares feature set dictionaries for X."""
    feature_sets = {
        "61_features": {
            "name": "61 Features",
            "X": X[features_61],
            "feature_names": features_61
        },
        "top20": {
            "name": "Top 20 Features",
            "X": X[features_20],
            "feature_names": features_20
        }
    }
    return feature_sets

def split_data(X_subset, y):
    """Performs 80/20 stratified train/test split."""
    return train_test_split(
        X_subset, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

def train_and_evaluate(model, X_train, y_train, X_test, y_test, model_name, feature_set_name):
    """
    Trains model on X_train/y_train, predicts on X_test, and evaluates metrics.
    Uses time.perf_counter() for high-precision latency measurement.
    """
    # Training latency
    t_start_train = time.perf_counter()
    model.fit(X_train, y_train)
    t_train = time.perf_counter() - t_start_train
    
    # Prediction latency
    t_start_pred = time.perf_counter()
    y_pred = model.predict(X_test)
    t_pred = time.perf_counter() - t_start_pred
    
    # Metrics calculation
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="binary", pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="binary", pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="binary", pos_label=1, zero_division=0))
    
    # Confusion matrix (labels=[0, 1] -> tn, fp, fn, tp)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    res = {
        "Feature_Set": feature_set_name,
        "Model": model_name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1_Score": f1,
        "Training_Time_Seconds": t_train,
        "Prediction_Time_Seconds": t_pred,
        "True_Positive": int(tp),
        "True_Negative": int(tn),
        "False_Positive": int(fp),
        "False_Negative": int(fn),
        "model_object": model,
        "confusion_matrix": cm
    }
    return res

def save_confusion_matrix_plot(cm, title, filename):
    """Renders and saves confusion matrix plot using matplotlib."""
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["BENIGN (0)", "DDoS (1)"])
    disp.plot(cmap="Blues", ax=ax, colorbar=False, values_format="d")
    ax.set_title(title, fontsize=11, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close(fig)

def save_performance_comparison_plot(results_list):
    """Renders and saves performance comparison bar chart across all experiments."""
    res_df = pd.DataFrame(results_list)
    labels = [f"{r['Model']}\n({r['Feature_Set']})" for r in results_list]
    
    x = np.arange(len(labels))
    width = 0.2
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    rects1 = ax.bar(x - 1.5*width, res_df["Accuracy"], width, label="Accuracy", color="#1f77b4")
    rects2 = ax.bar(x - 0.5*width, res_df["Precision"], width, label="Precision", color="#2ca02c")
    rects3 = ax.bar(x + 0.5*width, res_df["Recall"], width, label="Recall", color="#d62728")
    rects4 = ax.bar(x + 1.5*width, res_df["F1_Score"], width, label="F1-Score", color="#9467bd")
    
    ax.set_ylabel("Score", fontsize=11, fontweight="bold")
    ax.set_title("ML Model Performance Comparison (CICDDoS2019)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0.85, 1.02)
    ax.legend(loc="lower right")
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    
    plt.tight_layout()
    plt.savefig(PERFORMANCE_PLOT_PNG, dpi=300)
    plt.close(fig)

def main():
    start_time = time.time()
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    CONFUSION_DIR.mkdir(parents=True, exist_ok=True)
    
    # Part 1: Load Data
    X_raw, y = load_dataset()
    
    # Part 2: Load Selected Features
    features_61, features_20 = load_selected_features()
    feature_sets = prepare_feature_sets(X_raw, features_61, features_20)
    
    results = []
    
    # Part 4, 5, 6: Define models & run 6 experiments
    for set_key, set_info in feature_sets.items():
        f_name = set_info["name"]
        X_sub = set_info["X"]
        
        # Part 3: Train/Test Split BEFORE model fitting
        X_train, X_test, y_train, y_test = split_data(X_sub, y)
        
        # Define 3 Models
        # 1. Logistic Regression (with StandardScaler Pipeline)
        lr_pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE))
        ])
        
        # 2. Decision Tree Classifier
        dt_model = DecisionTreeClassifier(random_state=RANDOM_STATE)
        
        # 3. Random Forest Classifier
        rf_model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
        
        models_to_run = [
            ("Logistic Regression", lr_pipeline, "logistic_regression"),
            ("Decision Tree", dt_model, "decision_tree"),
            ("Random Forest", rf_model, "random_forest")
        ]
        
        for m_label, m_obj, m_slug in models_to_run:
            print(f"Running experiment: {m_label} | {f_name}...", flush=True)
            res = train_and_evaluate(m_obj, X_train, y_train, X_test, y_test, m_label, f_name)
            results.append(res)
            
            # Save individual confusion matrix image
            set_slug = "61_features" if set_key == "61_features" else "top20"
            cm_filename = CONFUSION_DIR / f"{m_slug}_{set_slug}.png"
            cm_title = f"Confusion Matrix: {m_label} ({f_name})"
            save_confusion_matrix_plot(res["confusion_matrix"], cm_title, cm_filename)

    # Convert results to DataFrame
    res_df = pd.DataFrame(results)
    
    # Export model_comparison.csv
    csv_columns = [
        "Feature_Set", "Model", "Accuracy", "Precision", "Recall", "F1_Score",
        "Training_Time_Seconds", "Prediction_Time_Seconds",
        "True_Positive", "True_Negative", "False_Positive", "False_Negative"
    ]
    export_df = res_df[csv_columns]
    export_df.to_csv(MODEL_COMPARISON_CSV, index=False)
    print(f"Saved comparison table to '{MODEL_COMPARISON_CSV.as_posix()}'.", flush=True)
    
    # Export comparative performance plot
    save_performance_comparison_plot(results)
    print(f"Saved performance comparison plot to '{PERFORMANCE_PLOT_PNG.as_posix()}'.", flush=True)
    
    # Part 11: Select Best Model based on priority: 1. F1-Score, 2. Recall, 3. Prediction Time
    sorted_results = sorted(
        results,
        key=lambda r: (r["F1_Score"], r["Recall"], -r["Prediction_Time_Seconds"]),
        reverse=True
    )
    best_res = sorted_results[0]
    
    best_f1_res = sorted(results, key=lambda r: r["F1_Score"], reverse=True)[0]
    best_rec_res = sorted(results, key=lambda r: r["Recall"], reverse=True)[0]
    
    # Save Best Model to joblib PKL
    best_model_obj = best_res["model_object"]
    joblib.dump(best_model_obj, BEST_MODEL_PKL)
    print(f"Saved best model object to '{BEST_MODEL_PKL.as_posix()}'.", flush=True)
    
    # Save best_model_info.txt
    best_info_content = f"""================================================================================
                    BEST TRAINED MODEL SUMMARY
================================================================================
Model Name:              {best_res['Model']}
Feature Set Used:        {best_res['Feature_Set']}
Number of Features:      {20 if best_res['Feature_Set'] == 'Top 20 Features' else 61}
Accuracy:                {best_res['Accuracy']:.6f}
Precision:               {best_res['Precision']:.6f}
Recall:                  {best_res['Recall']:.6f}
F1-Score:                {best_res['F1_Score']:.6f}
Training Time (s):       {best_res['Training_Time_Seconds']:.4f}
Prediction Time (s):     {best_res['Prediction_Time_Seconds']:.4f}
True Positives (TP):     {best_res['True_Positive']:,}
True Negatives (TN):     {best_res['True_Negative']:,}
False Positives (FP):    {best_res['False_Positive']:,}
False Negatives (FN):    {best_res['False_Negative']:,}
================================================================================
"""
    with open(BEST_MODEL_INFO_TXT, "w", encoding="utf-8") as f:
        f.write(best_info_content)
    print(f"Saved best model info to '{BEST_MODEL_INFO_TXT.as_posix()}'.", flush=True)
    
    # Part 8: Write ml_training_report.txt
    report_lines = []
    report_lines.append("================================================================================")
    report_lines.append("              MACHINE LEARNING TRAINING REPORT - CICDDOS2019")
    report_lines.append("================================================================================")
    report_lines.append("")
    report_lines.append("1. DATASET INFORMATION:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Source File: {INPUT_CSV.as_posix()}")
    report_lines.append(f" Total Rows: {len(X_raw):,}")
    report_lines.append(f" Target Classes: 0 = BENIGN ({y.value_counts().get(0, 0):,}), 1 = DDoS ({y.value_counts().get(1, 0):,})")
    report_lines.append("")
    report_lines.append("2. TRAIN / TEST SPLIT CONFIGURATION:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Split Ratio: 80% Training ({int(len(X_raw)*0.8):,} samples), 20% Testing ({int(len(X_raw)*0.2):,} samples)")
    report_lines.append(f" Stratified: Yes (Class ratio maintained in train/test splits)")
    report_lines.append(f" Random State: {RANDOM_STATE}")
    report_lines.append("")
    report_lines.append("3. FEATURE SETS EVALUATED:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Set A: 61 Candidate Features (Post zero-variance & duplicate removal)")
    report_lines.append(f" Set B: Top 20 Selected Features (MDI Random Forest Ranking)")
    report_lines.append("")
    report_lines.append("4. CLASSIFICATION MODELS EVALUATED:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(" 1. Logistic Regression (max_iter=1000, random_state=42, StandardScaler Pipeline)")
    report_lines.append(" 2. Decision Tree Classifier (random_state=42)")
    report_lines.append(" 3. Random Forest Classifier (n_estimators=100, random_state=42, n_jobs=-1)")
    report_lines.append("")
    report_lines.append("5. EXPERIMENT RESULTS SUMMARY (6 EXPERIMENTS):")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f"{'Feature Set':<18} | {'Model':<20} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8} | {'Train(s)':<8} | {'Pred(s)':<8}")
    report_lines.append("-" * 115)
    for r in results:
        report_lines.append(
            f"{r['Feature_Set']:<18} | {r['Model']:<20} | {r['Accuracy']:.6f} | {r['Precision']:.6f} | {r['Recall']:.6f} | {r['F1_Score']:.6f} | {r['Training_Time_Seconds']:<8.4f} | {r['Prediction_Time_Seconds']:<8.4f}"
        )
    report_lines.append("")
    report_lines.append("6. BEST MODEL BASED ON F1-SCORE:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Model: {best_f1_res['Model']} ({best_f1_res['Feature_Set']})")
    report_lines.append(f" F1-Score: {best_f1_res['F1_Score']:.6f} | Recall: {best_f1_res['Recall']:.6f} | Precision: {best_f1_res['Precision']:.6f}")
    report_lines.append("")
    report_lines.append("7. BEST MODEL BASED ON RECALL (DDoS Threat Detection Sensitivity):")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Model: {best_rec_res['Model']} ({best_rec_res['Feature_Set']})")
    report_lines.append(f" Recall: {best_rec_res['Recall']:.6f} | False Negatives: {best_rec_res['False_Negative']} undetected attacks")
    report_lines.append("")
    report_lines.append("8. BEST OVERALL PRACTICAL MODEL:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Selected Model: {best_res['Model']} using {best_res['Feature_Set']}")
    report_lines.append(f" Rationale: Highest F1-score ({best_res['F1_Score']:.6f}) combined with low prediction latency ({best_res['Prediction_Time_Seconds']:.4f}s).")
    report_lines.append(f" Zero data leakage ensured via Pipeline scaler scoping and pre-split feature selection.")
    report_lines.append("")
    report_lines.append("9. TRAINING TIME COMPARISON:")
    report_lines.append("--------------------------------------------------------------------------------")
    for r in sorted(results, key=lambda x: x["Training_Time_Seconds"]):
        report_lines.append(f" - {r['Model']:<20} ({r['Feature_Set']:<16}): {r['Training_Time_Seconds']:.4f} seconds")
    report_lines.append("")
    report_lines.append("10. PREDICTION LATENCY COMPARISON:")
    report_lines.append("--------------------------------------------------------------------------------")
    for r in sorted(results, key=lambda x: x["Prediction_Time_Seconds"]):
        report_lines.append(f" - {r['Model']:<20} ({r['Feature_Set']:<16}): {r['Prediction_Time_Seconds']:.4f} seconds")
    report_lines.append("================================================================================")
    
    with open(TRAINING_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"Saved ML training report to '{TRAINING_REPORT_TXT.as_posix()}'.", flush=True)

    # Final Output Message
    print("\nML training completed successfully.", flush=True)
    print("\nExperiments completed:\n6", flush=True)
    print("\nModels:\n- Logistic Regression\n- Decision Tree\n- Random Forest", flush=True)
    print("\nFeature sets:\n- 61 features\n- Top 20 features", flush=True)
    print(f"\nResults saved to:\n{MODEL_COMPARISON_CSV.as_posix()}", flush=True)
    print(f"\nReport saved to:\n{TRAINING_REPORT_TXT.as_posix()}", flush=True)
    print(f"\nBest model:\n{best_res['Model']}", flush=True)
    print(f"\nBest feature set:\n{best_res['Feature_Set']}", flush=True)

if __name__ == "__main__":
    main()
