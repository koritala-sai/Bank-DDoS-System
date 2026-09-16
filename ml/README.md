# Module 1: ML and DDoS Detection

This module is responsible for dataset preprocessing, feature engineering, model training, evaluation, and inference for classifying DDoS attack traffic targeting banking network infrastructure.

## Module Structure

- `notebooks/`: Exploratory Data Analysis (EDA) & Model Prototyping Jupyter Notebooks.
- `models/`: Directory for storing serialized trained models (`.joblib` format).
- `src/data_preprocessing.py`: Handles data cleaning, missing value imputation, and scaling.
- `src/feature_selection.py`: Selects top informative network flow attributes.
- `src/train_model.py`: Trains ML models (Random Forest, XGBoost, etc.).
- `src/evaluate_model.py`: Generates classification metrics (Accuracy, F1-Score, Confusion Matrix).
- `src/predict.py`: Performs inference on new network traffic samples.
