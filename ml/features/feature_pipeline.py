"""
Batch Feature Extraction Pipeline for Phishing Datasets.

Takes raw URL datasets, applies URLFeatureExtractor, and outputs
structured pandas DataFrames ready for Machine Learning training & evaluation.
"""

import os
import sys
import logging
from typing import Tuple
import pandas as pd

# Allow module to be run directly as a script from any directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ml.features.url_features import URLFeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class FeaturePipeline:
    """
    Transforms a DataFrame with a 'url' column into an engineered feature matrix.
    """

    def __init__(self):
        self.extractor = URLFeatureExtractor()

    def transform_dataframe(self, df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
        """
        Extracts features for all URLs in a DataFrame and returns a new DataFrame with feature columns.
        """
        if url_col not in df.columns:
            raise ValueError(f"Expected column '{url_col}' in DataFrame, found: {list(df.columns)}")

        logger.info(f"Extracting features for {len(df)} URLs...")
        
        feature_list = []
        for url in df[url_col]:
            feature_list.append(self.extractor.extract_features(str(url)))

        features_df = pd.DataFrame(feature_list)
        
        # Re-attach the label column if present in the input DataFrame
        if "label" in df.columns:
            features_df["label"] = df["label"].values

        logger.info(f"Feature extraction complete. Generated {features_df.shape[1]} columns.")
        return features_df

    def process_and_save(
        self,
        train_path: str = "ml/datasets/processed/train.csv",
        test_path: str = "ml/datasets/processed/test.csv",
        output_dir: str = "ml/datasets/processed"
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Extracts features from train and test raw splits, saving feature matrices as CSVs.
        """
        train_raw = pd.read_csv(train_path)
        test_raw = pd.read_csv(test_path)

        train_features = self.transform_dataframe(train_raw)
        test_features = self.transform_dataframe(test_raw)

        train_feat_path = os.path.join(output_dir, "train_features.csv")
        test_feat_path = os.path.join(output_dir, "test_features.csv")

        train_features.to_csv(train_feat_path, index=False)
        test_features.to_csv(test_feat_path, index=False)

        logger.info(f"Saved extracted features -> Train: {train_feat_path}, Test: {test_feat_path}")
        return train_features, test_features


if __name__ == "__main__":
    pipeline = FeaturePipeline()
    train_feat, test_feat = pipeline.process_and_save()
    print("\n--- Feature Matrix Preview ---")
    print(train_feat.head(3))
