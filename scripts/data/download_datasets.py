#!/usr/bin/env python3
"""Download public DDoS datasets for training and testing.

This script downloads common DDoS datasets such as CIC-IDS2017,
CSE-CIC-IDS2018, or others from public URLs.
"""

import argparse
import os
import sys
import requests
import zipfile
import tarfile
from pathlib import Path
from tqdm import tqdm

DATASETS = {
    "cic-ids2017": {
        "url": "https://www.unb.ca/cic/datasets/ids-2017.html",  # Need to get actual download link
        "description": "CIC-IDS2017 - Intrusion Detection Evaluation Dataset",
        "files": []
    },
    "cse-cic-ids2018": {
        "url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "description": "CSE-CIC-IDS2018 - Intrusion Detection Dataset",
        "files": []
    },
    "ddos-2019": {
        "url": "https://www.unb.ca/cic/datasets/ddos-2019.html",
        "description": "CIC-DDoS2019 - DDoS Attack Dataset",
        "files": []
    }
}


def download_file(url, dest_path, chunk_size=8192):
    """Download a file with progress bar."""
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    with open(dest_path, 'wb') as f:
        with tqdm(total=total_size, unit='B', unit_scale=True, desc=dest_path.name) as pbar:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    pbar.update(len(chunk))
    return dest_path


def extract_zip(zip_path, extract_to):
    """Extract zip file."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_to)


def extract_tar(tar_path, extract_to):
    """Extract tar/tar.gz file."""
    with tarfile.open(tar_path, 'r:*') as tf:
        tf.extractall(extract_to)


def download_cic_ids2017(output_dir):
    """Download CIC-IDS2017 dataset."""
    # Note: This is a placeholder; actual download requires navigating to the dataset page.
    # For demo, we'll simulate.
    print("Downloading CIC-IDS2017...")
    # In production, you would get the actual file URLs from the dataset provider.
    # Example:
    # url = "https://example.com/cic-ids2017.zip"
    # dest = Path(output_dir) / "cic-ids2017.zip"
    # download_file(url, dest)
    # extract_zip(dest, output_dir)
    print("CIC-IDS2017 dataset download not implemented. Please download manually.")


def download_cse_cic_ids2018(output_dir):
    """Download CSE-CIC-IDS2018 dataset."""
    print("CSE-CIC-IDS2018 dataset download not implemented. Please download manually.")


def download_ddos2019(output_dir):
    """Download CIC-DDoS2019 dataset."""
    print("CIC-DDoS2019 dataset download not implemented. Please download manually.")


def main():
    parser = argparse.ArgumentParser(description="Download DDoS datasets")
    parser.add_argument("--dataset", choices=DATASETS.keys(), help="Dataset to download")
    parser.add_argument("--output", default="data/raw", help="Output directory")
    parser.add_argument("--all", action="store_true", help="Download all datasets")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.all:
        for ds in DATASETS.keys():
            download_func = globals().get(f"download_{ds.replace('-', '_')}")
            if download_func:
                download_func(output_dir)
    elif args.dataset:
        download_func = globals().get(f"download_{args.dataset.replace('-', '_')}")
        if download_func:
            download_func(output_dir)
        else:
            print(f"No download function for {args.dataset}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()