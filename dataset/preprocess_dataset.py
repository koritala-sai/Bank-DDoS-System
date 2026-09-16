"""
Preprocessing Script for CICDDoS2019 Dataset (Memory-Safe Version)
AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks

This script performs chunked reading (chunksize=50000), identifier removal,
binary label encoding (BENIGN -> 0, DDoS -> 1), memory-safe incremental reservoir sampling (Algorithm R),
numeric coercion, infinity replacement, and median missing-value imputation
to produce a clean dataset capped at 50,000 BENIGN rows and 50,000 DDoS rows.
"""

import os
import sys
import time
import random
import numpy as np
import pandas as pd
from pathlib import Path

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================
TARGET_BENIGN = 50000       # Maximum BENIGN rows to retain
TARGET_DDOS = 50000         # Maximum DDoS rows to retain
CHUNK_SIZE = 50000          # Pandas read_csv chunk size for memory safety
MAX_ROWS_READ_PER_FILE = 100000 # Read up to 100k rows per file for fast balanced sampling

RAW_DIR = Path("dataset/raw")
PROCESSED_DIR = Path("dataset/processed")
OUTPUT_CSV_PATH = PROCESSED_DIR / "ddos_preprocessed.csv"
REPORT_TXT_PATH = PROCESSED_DIR / "preprocessing_report.txt"

# Non-predictive identifier columns to remove from ML features
COLUMNS_TO_REMOVE = [
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp"
]

def update_reservoir_df(reservoir_df, new_chunk_df, target_size, total_seen):
    """
    Vectorized Reservoir Sampling (Algorithm R variant) over DataFrame chunks.
    Maintains a uniform random sample of size target_size over streaming inputs.
    """
    n_new = len(new_chunk_df)
    if n_new == 0:
        return reservoir_df, total_seen
        
    curr_size = len(reservoir_df) if reservoir_df is not None else 0
    if curr_size < target_size:
        needed = target_size - curr_size
        to_add = new_chunk_df.iloc[:needed]
        if reservoir_df is None:
            reservoir_df = to_add.copy().reset_index(drop=True)
        else:
            reservoir_df = pd.concat([reservoir_df, to_add], ignore_index=True)
            
        total_seen += len(to_add)
        new_chunk_df = new_chunk_df.iloc[needed:]
        n_new = len(new_chunk_df)
        if n_new == 0:
            return reservoir_df, total_seen

    # Reservoir is full (curr_size == target_size)
    prob = target_size / (total_seen + n_new)
    k = int(np.random.binomial(n_new, min(1.0, prob)))
    if k > 0 and k <= target_size:
        sample_indices_new = np.random.choice(n_new, size=k, replace=False)
        sampled_new_values = new_chunk_df.iloc[sample_indices_new].values
        
        replace_indices_res = np.random.choice(target_size, size=k, replace=False)
        reservoir_df.iloc[replace_indices_res] = sampled_new_values
        
    total_seen += n_new
    return reservoir_df, total_seen

def preprocess_dataset():
    start_time = time.time()
    
    # Set random seeds for reproducible sampling
    random.seed(42)
    np.random.seed(42)
    
    # Create output directory automatically if it does not exist
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    
    if not RAW_DIR.exists():
        print(f"Error: Raw dataset directory '{RAW_DIR.as_posix()}' does not exist.", flush=True)
        return
        
    raw_files = sorted(list(RAW_DIR.rglob("*.csv")))
    total_files = len(raw_files)
    
    if total_files == 0:
        print(f"Error: No CSV files found in '{RAW_DIR.as_posix()}'.", flush=True)
        return
        
    print(f"Found {total_files} CSV files.", flush=True)
    print(f"Incremental reservoir sampling targets: max {TARGET_BENIGN:,} BENIGN rows, max {TARGET_DDOS:,} DDoS rows (chunksize={CHUNK_SIZE:,})...\n", flush=True)
    
    benign_reservoir_df = None
    ddos_reservoir_df = None
    total_benign_seen = 0
    total_ddos_seen = 0
    
    total_rows_read = 0
    raw_feature_count = None
    successful_files_count = 0
    skipped_files = []
    original_attack_labels = set()
    
    for idx, file_path in enumerate(raw_files, 1):
        filename = file_path.name
        print(f"Processing {idx}/{total_files}: {filename}", flush=True)
        
        file_rows = 0
        try:
            reader = None
            for enc in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    reader = pd.read_csv(
                        file_path,
                        chunksize=CHUNK_SIZE,
                        low_memory=False,
                        on_bad_lines='skip',
                        encoding=enc
                    )
                    break
                except Exception:
                    continue
                    
            if reader is None:
                raise ValueError("Failed to read CSV with utf-8/latin-1/cp1252 encodings")
                
            for chunk in reader:
                chunk.columns = [str(c).strip() for c in chunk.columns]
                
                if raw_feature_count is None:
                    raw_feature_count = len(chunk.columns)
                    
                chunk_len = len(chunk)
                total_rows_read += chunk_len
                file_rows += chunk_len
                
                label_col_matches = [c for c in chunk.columns if "label" in c.lower()]
                if not label_col_matches:
                    print(f"  Warning: No Label column found in {filename}, skipping chunk.", flush=True)
                    continue
                label_col = label_col_matches[-1]
                
                if label_col != "Label":
                    chunk = chunk.rename(columns={label_col: "Label"})
                    label_col = "Label"
                    
                chunk["Label"] = chunk["Label"].astype(str).str.strip()
                unique_chunk_labels = chunk["Label"].unique()
                for lbl in unique_chunk_labels:
                    if lbl:
                        original_attack_labels.add(lbl)
                        
                chunk["Binary_Label"] = (chunk["Label"].str.upper() != "BENIGN").astype(int)
                chunk = chunk.drop(columns=["Label"]).rename(columns={"Binary_Label": "Label"})
                
                cols_to_drop = [c for c in COLUMNS_TO_REMOVE if c in chunk.columns]
                chunk = chunk.drop(columns=cols_to_drop)
                
                benign_chunk = chunk[chunk["Label"] == 0]
                ddos_chunk = chunk[chunk["Label"] == 1]
                
                if len(benign_chunk) > 0:
                    benign_reservoir_df, total_benign_seen = update_reservoir_df(
                        benign_reservoir_df, benign_chunk, TARGET_BENIGN, total_benign_seen
                    )
                    
                if len(ddos_chunk) > 0:
                    ddos_reservoir_df, total_ddos_seen = update_reservoir_df(
                        ddos_reservoir_df, ddos_chunk, TARGET_DDOS, total_ddos_seen
                    )
                    
                if file_rows >= MAX_ROWS_READ_PER_FILE:
                    break
                    
            successful_files_count += 1
            
        except Exception as e:
            print(f"  Error processing {filename}: {str(e)}. Skipping file.", flush=True)
            skipped_files.append((filename, str(e)))
            continue

    b_count = len(benign_reservoir_df) if benign_reservoir_df is not None else 0
    d_count = len(ddos_reservoir_df) if ddos_reservoir_df is not None else 0

    print(f"\nCompleted reading chunks. Total rows read across files: {total_rows_read:,}", flush=True)
    print(f"Total BENIGN rows seen: {total_benign_seen:,} | Sampled: {b_count:,}", flush=True)
    print(f"Total DDoS rows seen:   {total_ddos_seen:,} | Sampled: {d_count:,}", flush=True)
    
    if b_count == 0 and d_count == 0:
        print("Error: No data rows were sampled from any file.", flush=True)
        return

    dfs_to_concat = []
    if benign_reservoir_df is not None and not benign_reservoir_df.empty:
        dfs_to_concat.append(benign_reservoir_df)
    if ddos_reservoir_df is not None and not ddos_reservoir_df.empty:
        dfs_to_concat.append(ddos_reservoir_df)
        
    df_sampled = pd.concat(dfs_to_concat, ignore_index=True)
    
    # Requirement: Ensure exact 50,000 BENIGN and 50,000 DDoS sub-sampling if available
    b_df = df_sampled[df_sampled["Label"] == 0]
    d_df = df_sampled[df_sampled["Label"] == 1]
    
    if len(b_df) > TARGET_BENIGN:
        b_df = b_df.sample(n=TARGET_BENIGN, random_state=42)
    if len(d_df) > TARGET_DDOS:
        d_df = d_df.sample(n=TARGET_DDOS, random_state=42)
        
    df_sampled = pd.concat([b_df, d_df], ignore_index=True)
    
    feature_cols = [c for c in df_sampled.columns if c != "Label"]
    
    for col in feature_cols:
        df_sampled[col] = pd.to_numeric(df_sampled[col], errors='coerce')
        
    inf_mask = np.isinf(df_sampled[feature_cols])
    infinity_count_handled = int(inf_mask.sum().sum())
    df_sampled[feature_cols] = df_sampled[feature_cols].replace([np.inf, -np.inf], np.nan)
    
    empty_cols = [col for col in feature_cols if df_sampled[col].isnull().all()]
    if empty_cols:
        print(f"Removing {len(empty_cols)} completely NaN columns: {empty_cols}", flush=True)
        df_sampled = df_sampled.drop(columns=empty_cols)
        feature_cols = [c for c in df_sampled.columns if c != "Label"]
        
    missing_before = int(df_sampled[feature_cols].isnull().sum().sum())
    missing_count_handled = missing_before
    
    for col in feature_cols:
        if df_sampled[col].isnull().any():
            col_median = df_sampled[col].median()
            if pd.isna(col_median):
                col_median = 0.0
            df_sampled[col] = df_sampled[col].fillna(col_median)
            
    df_final = df_sampled.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    label_counts = df_final["Label"].value_counts().to_dict()
    final_benign_count = int(label_counts.get(0, 0))
    final_ddos_count = int(label_counts.get(1, 0))
    
    df_final.to_csv(OUTPUT_CSV_PATH, index=False)
    
    elapsed_time = time.time() - start_time
    final_feature_names = list(df_final.columns)
    final_feature_count = len(final_feature_names) - 1
    
    skipped_str = "\n".join([f"  - {f}: {err}" for f, err in skipped_files]) if skipped_files else "  None"
    orig_labels_str = ", ".join(sorted(list(original_attack_labels))) if original_attack_labels else "None"
    
    report_content = f"""================================================================================
                    PREPROCESSING REPORT - CICDDOS2019
================================================================================
Number of raw CSV files found:          {total_files}
Number of files successfully processed: {successful_files_count}
Number of files skipped due to errors:  {len(skipped_files)}
Skipped files:
{skipped_str}

Total rows read:                        {total_rows_read:,}
Final rows retained:                    {len(df_final):,}
BENIGN count (0):                       {final_benign_count:,}
DDoS count (1):                         {final_ddos_count:,}

Original feature/column count:          {raw_feature_count}
Removed identifier columns:             {', '.join(COLUMNS_TO_REMOVE)}
Completely empty columns removed:       {', '.join(empty_cols) if empty_cols else 'None'}
Final feature count (excluding Label):  {final_feature_count}
Final dataset shape:                    {df_final.shape}

Missing values handled (imputed):       {missing_count_handled:,}
Infinity values handled:                {infinity_count_handled:,}

Original DDoS attack labels encountered:
  {orig_labels_str}

Final feature names ({len(final_feature_names)} columns):
  {', '.join(final_feature_names)}

Processing time:                        {elapsed_time:.2f} seconds
================================================================================
"""
    with open(REPORT_TXT_PATH, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print("\nPreprocessing completed successfully.", flush=True)
    print(f"Output: {OUTPUT_CSV_PATH.as_posix()}", flush=True)
    print(f"Report: {REPORT_TXT_PATH.as_posix()}", flush=True)

if __name__ == "__main__":
    preprocess_dataset()
