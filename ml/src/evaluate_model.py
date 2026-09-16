"""
Module 1: ML and DDoS Detection - Model Evaluation

Purpose:
Evaluate trained machine learning model performance using standard metrics:
Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and ROC-AUC curve.

Week 1 Status: Placeholder structure and API signatures.
"""


class ModelEvaluator:
    """Evaluates classifier performance on test set and generates evaluation reports."""
    
    def __init__(self, model):
        self.model = model

    def evaluate(self, X_test, y_test):
        """
        Computes performance metrics for binary/multiclass DDoS classification.
        
        Args:
            X_test: Test features
            y_test: Ground truth labels
            
        Returns:
            dict: Performance metrics (accuracy, precision, recall, f1_score)
        """
        # Placeholder signature for Week 1
        raise NotImplementedError("Model evaluation metrics will be implemented in future weeks.")
