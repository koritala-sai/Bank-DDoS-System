"""
Module 1: ML and DDoS Detection - Data Preprocessing

Purpose:
Clean raw network traffic datasets (e.g., CICDDoS2019 / CICIDS2017), clean missing/infinite values,
normalize numerical features, and encode target labels for model training.

Week 1 Status: Placeholder structure and API signatures. Model training will occur in future weeks.
"""

import pandas as pd
import numpy as np


class DataPreprocessor:
    """Handles dataset loading, missing value imputation, scaling, and preprocessing."""
    
    def __init__(self, raw_data_path=None):
        self.raw_data_path = raw_data_path
        
    def load_dataset(self, file_path):
        """
        Loads raw dataset from specified CSV path.
        
        Args:
            file_path (str): Path to CSV dataset
            
        Returns:
            pd.DataFrame: Loaded DataFrame
        """
        # Placeholder signature for Week 1
        raise NotImplementedError("Dataset loading will be implemented in Week 2.")

    def clean_data(self, df):
        """
        Removes duplicates, handles NaN and infinity values in network traffic features.
        
        Args:
            df (pd.DataFrame): Raw DataFrame
            
        Returns:
            pd.DataFrame: Cleaned DataFrame
        """
        # Placeholder signature for Week 1
        raise NotImplementedError("Data cleaning logic will be implemented in Week 2.")

    def scale_features(self, X_train, X_test):
        """
        Applies StandardScaler or MinMaxScaler to feature vectors.
        
        Args:
            X_train (np.ndarray): Training features
            X_test (np.ndarray): Testing features
            
        Returns:
            tuple: Scaled (X_train, X_test, scaler)
        """
        # Placeholder signature for Week 1
        raise NotImplementedError("Feature scaling will be implemented in Week 2.")
