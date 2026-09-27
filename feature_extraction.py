"""
Step 2: Feature Extraction
----------------------------
Reads data/raw_dataset.csv (url, label) and converts each URL into
numeric features a machine learning model can learn from.

Output:
  data/features_dataset.csv
"""

import os
import re
import socket
from urllib.parse import urlparse

import pandas as pd
import tldextract
import whois

INPUT_FILE = os.path.join("data", "raw_dataset.csv")
OUTPUT_FILE = os.path.join("data", "features_dataset.csv")

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "banking",
    "confirm", "signin", "password", "ebayisapi", "webscr",
]


def has_ip_address(hostname: str) -> int:
    try:
        socket.inet_aton(hostname)
        return 1
    except (socket.error, TypeError):
        return 0


def get_domain_age_days(hostname: str):
    """Returns domain age in days, or -1 if lookup fails (common for fake/new domains)."""
    try:
        w = whois.whois(hostname)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return -1
        import datetime
        age = (datetime.datetime.now() - creation).days
        return age
    except Exception:
        return -1


def extract_features(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    subdomain = ext.subdomain

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_ip": has_ip_address(hostname),
        "is_https": 1 if parsed.scheme == "https" else 0,
        "num_subdomains": len(subdomain.split(".")) if subdomain else 0,
        "suspicious_word_count": sum(
            1 for w in SUSPICIOUS_WORDS if w in url.lower()
        ),
        "url_has_port": 1 if parsed.port else 0,
        "path_length": len(parsed.path or ""),
        "hostname": hostname,
    }
    return features


def build_feature_dataset(lookup_domain_age: bool = False):
    df = pd.read_csv(INPUT_FILE)
    print(f"Loaded {len(df)} URLs from {INPUT_FILE}")

    records = []
    for i, row in df.iterrows():
        feats = extract_features(row["url"])
        if lookup_domain_age:
            feats["domain_age_days"] = get_domain_age_days(feats["hostname"])
        feats["label"] = row["label"]
        records.append(feats)

        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(df)}")

    out_df = pd.DataFrame(records)
    out_df = out_df.drop(columns=["hostname"])  # not a numeric feature
    out_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\nSaved {len(out_df)} rows with features to {OUTPUT_FILE}")
    print(f"Columns: {list(out_df.columns)}")


if __name__ == "__main__":
    # Domain age lookups (WHOIS) are slow and can time out for many URLs.
    # Set to True if you want it (recommended only for smaller datasets, e.g. <300 rows).
    build_feature_dataset(lookup_domain_age=False)
