import os
import json
import pandas as pd
from pathlib import Path

def get_human_readable_size(size_in_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} PB"

def inspect_dataset():
    raw_dir = Path("dataset/raw")
    output_dir = Path("dataset")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not raw_dir.exists():
        print(f"Error: Directory {raw_dir} does not exist.")
        return

    csv_files = sorted(list(raw_dir.rglob("*.csv")))
    
    file_analysis_list = []
    overall_labels = {}
    overall_identifiers = set()
    possible_label_cols_global = set()
    total_benign_count = 0
    total_ddos_count = 0
    attack_types_found = set()
    
    print(f"Found {len(csv_files)} CSV files in {raw_dir.as_posix()}")
    
    for idx, file_path in enumerate(csv_files, 1):
        try:
            rel_path = file_path.relative_to(Path.cwd()).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()
            
        size_bytes = file_path.stat().st_size
        size_human = get_human_readable_size(size_bytes)
        filename = file_path.name
        
        file_info = {
            "filename": filename,
            "relative_path": rel_path,
            "size_bytes": size_bytes,
            "size_human": size_human,
            "error": None,
            "number_of_columns": None,
            "column_names": [],
            "sample_shape": None,
            "first_3_rows": [],
            "data_types": {},
            "missing_values_in_sample": {},
            "total_missing_in_sample": 0,
            "duplicate_count_in_sample": 0,
            "possible_label_columns": [],
            "sample_label_distribution": {},
            "possible_identifier_columns": []
        }
        
        df = None
        for enc in ['utf-8', 'latin-1', 'cp1252']:
            try:
                df = pd.read_csv(file_path, nrows=2000, encoding=enc, low_memory=False, on_bad_lines='skip')
                break
            except Exception:
                continue
                
        if df is None:
            file_info["error"] = "Failed to read CSV file sample with utf-8/latin-1/cp1252 encodings"
            file_analysis_list.append(file_info)
            print(f"Error reading file [{idx}/{len(csv_files)}]: {filename}")
            continue
            
        # Clean column names (strip whitespace)
        df.columns = [str(c).strip() for c in df.columns]
        
        cols = list(df.columns)
        file_info["number_of_columns"] = len(cols)
        file_info["column_names"] = cols
        file_info["sample_shape"] = list(df.shape)
        
        # First 3 rows sanitized for JSON
        first_3 = df.head(3).to_dict(orient="records")
        file_info["first_3_rows"] = json.loads(pd.Series(first_3).to_json(default_handler=str))
        
        # Data types summary
        file_info["data_types"] = {col: str(dtype) for col, dtype in df.dtypes.items()}
        
        # Missing values
        missing_series = df.isnull().sum()
        missing_dict = {col: int(val) for col, val in missing_series.items() if val > 0}
        file_info["missing_values_in_sample"] = missing_dict
        file_info["total_missing_in_sample"] = int(missing_series.sum())
        
        # Duplicates
        file_info["duplicate_count_in_sample"] = int(df.duplicated().sum())
        
        # Identify possible label columns
        label_keywords = ["label", "attack", "class"]
        possible_labels = [c for c in cols if any(kw in c.lower() for kw in label_keywords)]
        file_info["possible_label_columns"] = possible_labels
        for pl in possible_labels:
            possible_label_cols_global.add(pl)
            
        # Label distribution if label column exists
        if possible_labels:
            target_col = possible_labels[-1]
            val_counts = df[target_col].value_counts().to_dict()
            file_info["sample_label_distribution"] = {str(k).strip(): int(v) for k, v in val_counts.items()}
            
            for lbl, count in file_info["sample_label_distribution"].items():
                lbl_clean = str(lbl).strip()
                overall_labels[lbl_clean] = overall_labels.get(lbl_clean, 0) + count
                if "benign" in lbl_clean.lower():
                    total_benign_count += count
                else:
                    total_ddos_count += count
                    attack_types_found.add(lbl_clean)
                    
        # Identify possible identifier columns
        id_keywords = ["flow id", "source ip", "destination ip", "timestamp", "source port", "destination port", "unnamed: 0", "index", "simultaneous interactions"]
        possible_ids = [c for c in cols if any(kw in c.lower() for kw in id_keywords)]
        file_info["possible_identifier_columns"] = possible_ids
        for pid in possible_ids:
            overall_identifiers.add(pid)
            
        file_analysis_list.append(file_info)
        print(f"Processed [{idx}/{len(csv_files)}]: {filename} ({size_human}, {len(cols)} cols)")

    # Build machine-readable JSON summary
    summary_data = {
        "total_csv_files_found": len(csv_files),
        "files_analyzed": len(file_analysis_list),
        "global_possible_label_columns": sorted(list(possible_label_cols_global)),
        "global_possible_identifier_columns": sorted(list(overall_identifiers)),
        "observed_labels_summary": overall_labels,
        "traffic_types_detected": {
            "has_benign": total_benign_count > 0,
            "has_ddos": total_ddos_count > 0,
            "multiple_attack_types": len(attack_types_found) > 1,
            "attack_types": sorted(list(attack_types_found))
        },
        "files": file_analysis_list
    }
    
    json_path = output_dir / "dataset_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)
    print(f"\nSaved machine-readable summary to {json_path.as_posix()}")
    
    # Build text report
    report_lines = []
    report_lines.append("================================================================================")
    report_lines.append("           DATASET ANALYSIS REPORT - DDOS DETECTION CAPSTONE PROJECT")
    report_lines.append("================================================================================")
    report_lines.append("")
    report_lines.append(f"A. TOTAL NUMBER OF CSV FILES FOUND: {len(csv_files)}")
    report_lines.append("")
    report_lines.append("B. LIST OF FILES & C. FILE SIZES:")
    report_lines.append("--------------------------------------------------------------------------------")
    for f_info in file_analysis_list:
        report_lines.append(f" - Path: {f_info['relative_path']}")
        report_lines.append(f"   Filename: {f_info['filename']}")
        report_lines.append(f"   Size: {f_info['size_human']} ({f_info['size_bytes']} bytes)")
        report_lines.append("")

    report_lines.append("D. COLUMNS FOR EACH FILE:")
    report_lines.append("--------------------------------------------------------------------------------")
    for f_info in file_analysis_list:
        report_lines.append(f" File: {f_info['filename']} ({f_info['number_of_columns']} columns)")
        if f_info['error']:
            report_lines.append(f"   ERROR: {f_info['error']}")
        else:
            report_lines.append(f"   Columns ({len(f_info['column_names'])}): {', '.join(f_info['column_names'])}")
        report_lines.append("")

    report_lines.append("E. POSSIBLE LABEL COLUMNS:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(f" Globally identified label column candidate(s): {', '.join(sorted(list(possible_label_cols_global))) or 'None'}")
    for f_info in file_analysis_list:
        report_lines.append(f" - {f_info['filename']}: {', '.join(f_info['possible_label_columns']) or 'None'}")
    report_lines.append("")

    report_lines.append("F. OBSERVED LABELS FROM SAMPLES:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(" Aggregated Label Frequencies across sampled rows (2000 rows/file):")
    for lbl, cnt in sorted(overall_labels.items(), key=lambda x: x[1], reverse=True):
        report_lines.append(f"   * {lbl}: {cnt} samples")
    report_lines.append("")
    report_lines.append(f" BENIGN / Normal traffic found: {'YES' if total_benign_count > 0 else 'NO'}")
    report_lines.append(f" DDoS traffic found: {'YES' if total_ddos_count > 0 else 'NO'}")
    report_lines.append(f" Multiple attack types found: {'YES' if len(attack_types_found) > 1 else 'NO'}")
    report_lines.append(f" Distinct attack categories detected: {', '.join(sorted(list(attack_types_found)))}")
    report_lines.append("")

    report_lines.append("G. POSSIBLE IDENTIFIER COLUMNS:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(" Columns containing network/record identifiers (to exclude from ML feature matrix):")
    for pid in sorted(list(overall_identifiers)):
        report_lines.append(f"   * {pid}")
    report_lines.append("")

    report_lines.append("H. MISSING-VALUE OBSERVATIONS:")
    report_lines.append("--------------------------------------------------------------------------------")
    any_missing = False
    for f_info in file_analysis_list:
        if f_info['total_missing_in_sample'] > 0:
            any_missing = True
            report_lines.append(f" - {f_info['filename']}: {f_info['total_missing_in_sample']} missing cells in sample")
            for col, count in f_info['missing_values_in_sample'].items():
                report_lines.append(f"     -> Column '{col}': {count} missing")
    if not any_missing:
        report_lines.append(" No missing values detected in the 2000-row samples across all files.")
    report_lines.append("")

    report_lines.append("I. DUPLICATE OBSERVATIONS:")
    report_lines.append("--------------------------------------------------------------------------------")
    for f_info in file_analysis_list:
        report_lines.append(f" - {f_info['filename']}: {f_info['duplicate_count_in_sample']} duplicate rows in 2000-row sample")
    report_lines.append("")

    report_lines.append("J. INITIAL RECOMMENDATIONS FOR PREPROCESSING:")
    report_lines.append("--------------------------------------------------------------------------------")
    report_lines.append(" 1. Column Name Sanitization: Strip leading and trailing whitespace from column names (e.g., ' Label' -> 'Label').")
    report_lines.append(" 2. Identifier Removal: Drop non-predictive network flow metadata during feature engineering (e.g., Flow ID, Source IP, Destination IP, Timestamp, Source Port, Destination Port, Unnamed: 0).")
    report_lines.append(" 3. Data Cleaning: Handle infinity (np.inf, -np.inf) and NaN values in numerical flow stats columns (e.g., Flow Bytes/s, Flow Packets/s).")
    report_lines.append(" 4. Class Harmonization: Map multi-class DDoS labels (e.g., DrDoS_DNS, Syn, UDP, TFTP, UDPLag) into binary (0=BENIGN, 1=DDoS) and multiclass mappings.")
    report_lines.append(" 5. Scalable Processing: Use chunking (e.g., chunksize=100,000) or PySpark/Dask/Polars when processing full raw CSV files to prevent Out-Of-Memory (OOM) errors.")
    report_lines.append("================================================================================")

    report_path = output_dir / "dataset_analysis_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"Saved human-readable report to {report_path.as_posix()}")

if __name__ == "__main__":
    inspect_dataset()