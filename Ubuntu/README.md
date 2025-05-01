# Infectious-Virus-Detection-System

## Overview

The Infectious Virus Detection System is a hybrid security solution that combines traditional signature-based virus scanning, process and file monitoring, and machine learning-based malware detection. It is designed to run on Linux systems and provides both real-time monitoring and offline analysis capabilities.

The system consists of:
- **C-based modules** for fast file scanning, process monitoring, and real-time alerts.
- **Python scripts** for preparing data, training a machine learning model, and predicting malicious activity.
- **A large virus signature database** for hash-based detection.

---

## Features

- **Signature-Based File Scanning:** Uses MD5 hashes and a large signature database to detect known viruses.
- **Process Monitoring:** Scans running processes for suspicious activity (e.g., high CPU usage, suspicious commands).
- **File and Directory Monitoring:** Uses inotify to watch for file creation, deletion, and modification in real time.
- **Network Activity Monitoring:** Detects unusual network connections by monitoring process network activity.
- **Machine Learning Detection:** Trains a Random Forest model to classify files/processes as benign or malicious based on extracted features.
- **Alerting:** Logs and displays alerts for suspicious activity, with optional desktop notifications.

---

## Directory Structure

```
.
├── main.c, scan.c, scan.h, process.c, process.h, monitor.c, alerts.c, alerts.h
├── task4_moniter.c         # Advanced monitoring (file, process, network, notifications)
├── Makefile                # For building the C components
├── signatures.txt          # Large database of known virus signatures (MD5 hashes)
├── combined_labeled_dataset.csv, X_train.csv, X_test.csv, y_train.csv, y_test.csv
├── prepare_data.py         # Prepares and splits data for ML
├── train_model.py          # Trains the Random Forest model
├── predict_malicious.py    # Uses the trained model for predictions
├── virus_detection_model.pkl # Saved ML model
├── new_data_check.csv      # Example input for prediction
├── testfile.txt            # Example file for scanning
└── README.md
```

---

## Requirements

### C Components

- GCC (with pthread, OpenSSL, and inotify support)
- Libraries: `libssl-dev`, `libcrypto++-dev`, `libnotify-dev`, `libtlsh-dev` (for advanced monitoring)

### Python Components

- Python 3.x
- `pandas`
- `scikit-learn`
- `joblib`

Install Python dependencies with:
```bash
pip install pandas scikit-learn joblib
```

---

## Building and Running

### 1. Build the C Virus Scanner

```bash
make
```

This will produce an executable named `virus_scan`.

### 2. Run the File and Process Scanner

```bash
./virus_scan
```

- By default, it scans a hardcoded file and running processes.
- To change the file or directory to scan, modify `main.c` accordingly.

### 3. Advanced Monitoring (Task 4)

To use real-time file, process, and network monitoring with desktop notifications:

```bash
gcc task4_moniter.c alerts.c -o virus_monitor -lnotify
./virus_monitor
```

- Edit the `path` variable in `task4_moniter.c` to set the directory to monitor.

---

## Machine Learning Workflow

### 1. Prepare Data

Ensure `combined_labeled_dataset.csv` is present. Then run:

```bash
python prepare_data.py
```

This will generate `X_train.csv`, `X_test.csv`, `y_train.csv`, and `y_test.csv`.

### 2. Train the Model

```bash
python train_model.py
```

This will train a Random Forest classifier and save it as `virus_detection_model.pkl`.

### 3. Predict on New Data

Prepare your new data in the same format as the training data and save as `new_data_check.csv`. Then run:

```bash
python predict_malicious.py
```

The script will output whether the sample is benign (`0`) or malicious (`1`).

---

## Customization

- **Signature Database:** Add or update MD5 hashes in `signatures.txt` to improve detection.
- **Monitoring Directory:** Change the monitored path in `task4_moniter.c` or `monitor.c`.
- **Feature Engineering:** Modify `prepare_data.py` to add or remove features for the ML model.

---

## Logs and Alerts

- Suspicious activity is logged to `suspicious_activity.log`.
- Alerts are printed to the console and, if using advanced monitoring, as desktop notifications.

---

## Notes

- The C components are designed for Linux and use `/proc` and `inotify`.
- The ML model expects preprocessed data; ensure your new samples match the feature format.
- The signature database (`signatures.txt`) can be very large; ensure your system has enough memory.

---
