"""
Dataset Ingestion, Cleaning, and Validation Pipeline for Phishing URL Detection.

This module is responsible for:
1. Loading raw URL datasets (CSV / text).
2. Data validation & integrity checks (nulls, malformed strings).
3. Deduplication and conflicting label resolution.
4. Label standardization (0 = Legitimate, 1 = Phishing).
5. Stratified train/test dataset splitting to prevent data leakage.
"""

import os
import logging
from typing import Tuple, Optional
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def create_initial_sample_dataset(output_path: str = "ml/datasets/raw/sample_urls.csv") -> str:
    """
    Creates a verified baseline dataset containing real-world patterns of
    both legitimate and phishing URLs for initial pipeline development and testing.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    sample_data = [
        # --- Legitimate URLs (Label: 0) ---
        ("https://www.google.com", 0),
        ("https://www.google.com/search?q=machine+learning+tutorial", 0),
        ("https://www.google.com/maps/place/New+York", 0),
        ("https://www.github.com/torvalds/linux", 0),
        ("https://github.com/scikit-learn/scikit-learn/pull/1234", 0),
        ("https://en.wikipedia.org/wiki/Machine_learning", 0),
        ("https://en.wikipedia.org/wiki/Cybersecurity", 0),
        ("https://stackoverflow.com/questions/tagged/python", 0),
        ("https://stackoverflow.com/questions/1234567/how-to-do-x", 0),
        ("https://www.amazon.com/dp/B08N5WRWNW", 0),
        ("https://www.amazon.com/gp/help/customer/display.html", 0),
        ("https://www.microsoft.com/en-us/software-download", 0),
        ("https://support.microsoft.com/en-us/windows", 0),
        ("https://www.apple.com/iphone-15-pro/", 0),
        ("https://developer.apple.com/documentation/", 0),
        ("https://docs.python.org/3/library/urllib.parse.html", 0),
        ("https://pypi.org/project/scikit-learn/", 0),
        ("https://netflix.com/browse", 0),
        ("https://www.linkedin.com/feed/", 0),
        ("https://news.ycombinator.com/item?id=30000000", 0),
        ("https://arxiv.org/abs/1706.03762", 0),
        ("https://developer.mozilla.org/en-US/docs/Web/HTTP", 0),
        ("https://www.reddit.com/r/MachineLearning/", 0),
        ("https://kaggle.com/datasets", 0),
        ("https://fastapi.tiangolo.com/tutorial/", 0),
        ("https://pandas.pydata.org/docs/reference/", 0),
        ("https://hub.docker.com/_/python", 0),
        ("https://cloudflare.com/learning/security/threats/phishing/", 0),
        ("https://www.nytimes.com/section/technology", 0),
        ("https://www.bbc.com/news/world", 0),
        ("https://www.cnn.com/world", 0),
        ("https://www.chase.com/personal/banking", 0),
        ("https://www.bankofamerica.com/online-banking/", 0),
        ("https://www.wellsfargo.com/help/", 0),
        ("https://www.paypal.com/us/home", 0),
        ("https://slack.com/help", 0),
        ("https://zoom.us/join", 0),
        ("https://www.dropbox.com/features/cloud-storage", 0),
        ("https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M", 0),
        ("https://twitter.com/explore", 0),
        ("https://www.facebook.com/policies", 0),
        ("https://www.instagram.com/accounts/login/", 0),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 0),
        ("https://aws.amazon.com/console/", 0),
        ("https://cloud.google.com/products", 0),
        ("https://portal.azure.com/", 0),
        ("https://www.coursera.org/specializations/deep-learning", 0),
        ("https://www.edx.org/course/introduction-to-computer-science", 0),
        ("https://medium.com/topic/cybersecurity", 0),
        ("https://techcrunch.com/enterprise/", 0),
        
        # --- Phishing / Malicious URLs (Label: 1) ---
        ("http://paypa1-update-security-account.com/login.php", 1),
        ("http://192.168.1.100/secure/bankofamerica/verify.html", 1),
        ("http://appleid.apple.com.account-verification-notice.xyz/signin", 1),
        ("http://netflix-billing-update-warning.com/customer/update", 1),
        ("http://login.microsoftonline.com.secure-token-id9483.cc/auth", 1),
        ("http://secure-login-wellsfargo-portal.com/auth/login", 1),
        ("http://amaz0n-security-alert-center.top/orders/reverify", 1),
        ("http://chase-bank-online-alert.account-update921.info/login", 1),
        ("http://steamcommunity.com-trade-offer-confirm7291.org/trade", 1),
        ("http://binance-account-recovery-verify-id.tk/wallet/login", 1),
        ("http://dhl-package-tracking-reschedule.com/delivery/confirm", 1),
        ("http://metamask-extension-seed-recovery.icu/phrase.html", 1),
        ("http://facebook-security-verification-portal.biz/security", 1),
        ("http://instagram-copyright-infringement-appeal.site/appeal", 1),
        ("http://google-drive-shared-document-verify.ga/file/view", 1),
        ("http://paypal.com@secure-billing-portal.com/login?cmd=_login", 1),
        ("http://irs-tax-refund-status-portal-gov.info/refund/claim", 1),
        ("http://support-helpdesk-urgent-ticket928.pw/reset-password", 1),
        ("http://adobe-pdf-shared-cloud-reader.top/download/doc", 1),
        ("http://whatsapp-web-login-qr-sync.net/web/session", 1),
        ("http://185.220.101.5/bank/login.php?attempt=1&session=invalid", 1),
        ("http://secure.wellsfargo.com.security-check-user.xyz/auth", 1),
        ("http://account-update-portal-citi-secure.info/citi/login", 1),
        ("http://coinbase-auth-2fa-verification.top/signin", 1),
        ("http://usps-tracking-package-address-confirm.online/track", 1),
        ("http://fedex-express-delivery-redirection.site/schedule", 1),
        ("http://office365-password-expiration-warning.link/renew", 1),
        ("http://bankofamerica.com.account-suspension-resolve.org/login", 1),
        ("http://american-express-card-alert-verification.com/amx", 1),
        ("http://dropbox-shared-invoice-view.cf/document/pdf", 1),
        ("http://paypal-resolution-center-case99482.com/dispute", 1),
        ("http://apple-icloud-find-lost-device-locate.vip/login", 1),
        ("http://att-yahoo-mail-upgrade-server-migration.click/login", 1),
        ("http://quickbooks-invoice-payment-overdue.online/invoice", 1),
        ("http://roblox-free-robux-generator-giveaway.tk/claim", 1),
        ("http://discord-nitro-free-gift-airdrop.xyz/nitro", 1),
        ("http://linkedin-account-security-incident-alert.co/verify", 1),
        ("http://kraken-exchange-withdraw-confirmation.icu/auth", 1),
        ("http://uber-driver-payout-verification-failed.top/bank", 1),
        ("http://airbnb-booking-payment-protection.pw/checkout", 1),
        ("http://198.51.100.24/auth/webscr.php?cmd=_login-run", 1),
        ("http://secure-login.chase.com.session-renew-91823.info/auth", 1),
        ("http://myetherwallet-keystore-unlock-privatekey.cc/unlock", 1),
        ("http://amazon-prime-membership-cancellation-refund.site/help", 1),
        ("http://turbotax-direct-deposit-audit-clearance.top/irs", 1),
        ("http://walmart-gift-card-survey-winner-claim.club/win", 1),
        ("http://verizon-wireless-bill-rebate-claim.link/login", 1),
        ("http://zoom-meeting-invite-recordings-access.bid/join", 1),
        ("http://hulu-subscription-billing-update-required.xyz/auth", 1),
        ("http://gmail-storage-full-upgrade-verify.space/drive", 1)
    ]
    
    df = pd.DataFrame(sample_data, columns=["url", "label"])
    df.to_csv(output_path, index=False)
    logger.info(f"Sample raw dataset created at {output_path} with {len(df)} samples.")
    return output_path


def load_raw_dataset(filepath: str, url_col: str = "url", label_col: str = "label") -> pd.DataFrame:
    """
    Loads a raw CSV file and standardizes column names.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found at: {filepath}")
    
    df = pd.read_csv(filepath)
    logger.info(f"Loaded raw dataset with shape: {df.shape}")
    
    if url_col not in df.columns or label_col not in df.columns:
        raise ValueError(f"Columns '{url_col}' and/or '{label_col}' not found in CSV. Found: {list(df.columns)}")
    
    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label"})
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans raw dataset:
    1. Removes null and empty URLs.
    2. Strips whitespace.
    3. Standardizes labels to integers (0 = Legitimate, 1 = Phishing).
    4. Handles conflicting labels by dropping ambiguous URLs.
    5. Deduplicates exact matches.
    """
    initial_count = len(df)
    
    # 1. Drop missing values
    df = df.dropna(subset=["url", "label"]).copy()
    
    # 2. String cleanup
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    
    # 3. Label normalization (handles strings like 'phishing'/'legitimate' or 1/0 or -1/1)
    if df["label"].dtype == object:
        mapping = {
            "phishing": 1, "bad": 1, "malicious": 1, "1": 1, 1: 1,
            "legitimate": 0, "good": 0, "benign": 0, "0": 0, 0: 0, "-1": 0, -1: 0
        }
        df["label"] = df["label"].astype(str).str.lower().str.strip().map(mapping)
    elif set(df["label"].unique()) == {-1, 1}:
        # UCI dataset convention: -1 = Phishing/Legitimate depending on source, standard is -1/1
        df["label"] = df["label"].map({-1: 0, 1: 1})
    
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)
    
    # 4. Check for conflicting labels (same URL having both label 0 and label 1)
    label_variance = df.groupby("url")["label"].nunique()
    conflicted_urls = label_variance[label_variance > 1].index
    if len(conflicted_urls) > 0:
        logger.warning(f"Found {len(conflicted_urls)} URLs with conflicting labels. Dropping them for label integrity.")
        df = df[~df["url"].isin(conflicted_urls)]
    
    # 5. Deduplicate
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    
    logger.info(f"Cleaned dataset: {initial_count} raw rows -> {len(df)} valid, unique rows.")
    return df


def split_and_save_data(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42,
    processed_dir: str = "ml/datasets/processed"
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Performs stratified train/test split and saves results to processed directory.
    Stratification ensures both splits have the exact same ratio of phishing to legitimate URLs.
    """
    os.makedirs(processed_dir, exist_ok=True)
    
    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=random_state,
        stratify=df["label"]
    )
    
    train_path = os.path.join(processed_dir, "train.csv")
    test_path = os.path.join(processed_dir, "test.csv")
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    logger.info(f"Train split saved to {train_path} ({len(train_df)} samples, {train_df['label'].mean():.1%} phishing)")
    logger.info(f"Test split saved to {test_path} ({len(test_df)} samples, {test_df['label'].mean():.1%} phishing)")
    
    return train_df, test_df


if __name__ == "__main__":
    # Test the complete data ingestion & cleaning pipeline
    sample_file = create_initial_sample_dataset()
    raw_df = load_raw_dataset(sample_file)
    clean_df = clean_dataset(raw_df)
    train_df, test_df = split_and_save_data(clean_df)
    print("\n--- Pipeline Execution Summary ---")
    print(f"Total Cleaned Samples: {len(clean_df)}")
    print(f"Class Distribution:\n{clean_df['label'].value_counts(normalize=True)}")
