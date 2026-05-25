# Infectious-Virus-Detection-System

Infectious Virus Detection System is a cross-platform malware detection and monitoring project with separate Windows and Ubuntu implementations. The repository combines signature-based scanning, behavioral analysis, real-time system monitoring, alerting, and machine learning to simulate a multi-layered defense workflow.

The project is split into two platform-focused tracks:

- `Windows/`: a Win32-first detection and response pipeline with recursive folder scanning, multithreaded signature matching, process containment, registry watching, folder telemetry, native alerting, email escalation, and a Detours-backed API-hooking layer prepared for deeper behavioral instrumentation.
- `Ubuntu/`: a Linux implementation built around C monitoring modules, `/proc` and `inotify`-style visibility, and a Python-based machine learning workflow for offline malware classification.

## Contributors

- Windows implementation and behavioral-analysis pipeline: **Shivanshu Verma**
- Ubuntu implementation and Linux/ML workflow: **Abhishek Yadav**

## Project Highlights

- Hybrid detection model combining known-signature matching with runtime behavioral monitoring.
- Platform-specific implementations instead of a shallow cross-platform port.
- Automated response flow that escalates from detection to alerting, monitoring, and containment.
- Windows behavioral analysis built on native OS telemetry, with Microsoft Detours included for API interception expansion.
- Ubuntu pipeline extended with dataset preparation, model training, and prediction scripts for machine-learning-assisted analysis.

## Repository Layout

```text
.
├── Windows/
│   ├── detours/
│   │   └── include/detours.h
│   ├── include/
│   │   ├── alert_box.h
│   │   ├── behavioral_analysis.h
│   │   └── virus_signature.h
│   ├── src/
│   │   ├── alert_box.c
│   │   ├── behavioral_analysis.c
│   │   ├── email.c
│   │   ├── main.c
│   │   ├── main.old
│   │   ├── send_email.py
│   │   └── virus_signature.c
│   └── MakeFile
├── Ubuntu/
│   ├── alerts.c / alerts.h
│   ├── main.c
│   ├── monitor.c
│   ├── process.c / process.h
│   ├── scan.c / scan.h
│   ├── task4_moniter.c
│   ├── prepare_data.py
│   ├── train_model.py
│   ├── predict_malicious.py
│   ├── virus_detection_model.pkl
│   ├── signatures.txt
│   └── README.md
└── README.md
```

## Windows Implementation

The Windows branch is the more response-oriented part of the project. It is designed as a staged detection pipeline that starts with filesystem triage and escalates into live behavioral monitoring once a suspicious file is found.

### Windows Detection Flow

1. `Windows/src/main.c` recursively traverses a target directory.
2. Every regular file is hashed with the WinCrypt API in `Windows/src/virus_signature.c`.
3. A CSV-driven signature database is searched in parallel using four worker threads.
4. When a signature matches:
   - the infected file path is reported to the console
   - a native Windows alert box is shown
   - an email notification is triggered through a Python helper
   - behavioral monitoring starts for the infected folder and executable name
5. `Windows/src/behavioral_analysis.c` launches concurrent runtime monitors for:
   - suspicious process discovery and termination
   - directory change tracking with `ReadDirectoryChangesW`
   - registry persistence tracking under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### Windows Features

- **Recursive folder scanning:** Walks a complete directory tree instead of only checking a single file.
- **WinCrypt MD5 hashing:** Uses Windows CryptoAPI to generate file fingerprints.
- **Multithreaded signature search:** Splits the signature database across four comparison threads for faster matching.
- **Native Win32 alerting:** Displays a warning dialog through `MessageBoxA` as soon as a threat is identified.
- **Automated email escalation:** Sends a detection summary containing the file name, folder path, and hash.
- **Process containment:** Continuously enumerates live processes and terminates a matching suspicious executable.
- **Real-time folder telemetry:** Watches the infected directory and logs file changes as they happen.
- **Registry persistence monitoring:** Tracks updates to the Windows Run key to surface suspicious autorun behavior.
- **Behavior logging:** Writes behavioral events to `behavior_analysis.log` for later review.
- **Detours-based hook scaffolding:** The codebase includes Microsoft Detours headers and hook handlers for `CreateFileW` and `RegSetValueExW`, giving the Windows build an advanced path toward user-mode API interception and persistence-aware telemetry.

### Windows Technology Stack

- **Win32 APIs:** `CreateFile`, `ReadFile`, `ReadDirectoryChangesW`, `CreateToolhelp32Snapshot`, `TerminateProcess`, `RegNotifyChangeKeyValue`, `MessageBoxA`
- **Crypto:** Windows CryptoAPI (`CryptAcquireContext`, `CryptCreateHash`, `CryptHashData`, `CryptGetHashParam`)
- **Hooking layer:** Microsoft Detours header package included under `Windows/detours/`
- **Notification helper:** Python SMTP script for outbound alert emails

### Building on Windows

The current source layout is easiest to build as a single translation unit because `src/main.c` directly includes the other implementation files.

```powershell
cd Windows
gcc -Iinclude src/main.c -o virus_checker -lcrypt32 -luser32 -ladvapi32
```

This produces `virus_checker.exe`.

### Running on Windows

```powershell
.\virus_checker.exe path\to\virus_signatures.csv path\to\folder_to_scan
```

Expected CSV format for the signature database:

```csv
44d88612fea8a8f36de82e1278abb02f,eicar-test-file
d41d8cd98f00b204e9800998ecf8427e,suspicious-empty-file
```

### Key Windows Modules

- `Windows/src/main.c`: orchestrates recursive scanning and response handling
- `Windows/src/virus_signature.c`: loads CSV signatures, computes MD5 hashes, and performs threaded matching
- `Windows/src/behavioral_analysis.c`: handles folder monitoring, registry monitoring, process termination, and Detours hook definitions
- `Windows/src/alert_box.c`: displays native Windows threat popups
- `Windows/src/email.c`: invokes the Python email helper
- `Windows/src/send_email.py`: sends SMTP alerts
- `Windows/src/main.old`: earlier single-file scan variant retained for reference

### Windows Notes

- The repository already includes Detours hook handlers for `CreateFileW` and `RegSetValueExW`. The explicit attach/detach transaction block is present in `behavioral_analysis.c` and can be enabled if you want to extend the project into active API interception.
- Email notifications are driven by `Windows/src/send_email.py`. Update the SMTP configuration and script path for your own environment before using it.
- The checked-in `Windows/MakeFile` is a minimal build stub. The manual `gcc` command above matches the current source layout more reliably.

## Ubuntu Implementation

The Ubuntu branch combines classic malware-scanning techniques with Linux monitoring primitives and a machine learning workflow for offline detection experiments.

### Ubuntu Features

- **Signature-based file scanning:** Uses MD5 hashes and `signatures.txt` to detect known threats.
- **Process monitoring:** Inspects running processes and flags suspicious commands or activity patterns.
- **File and directory monitoring:** Watches filesystem events in real time.
- **Network activity monitoring:** Tracks unusual process network behavior in the advanced monitor.
- **Machine learning pipeline:** Uses Python scripts to prepare data, train a Random Forest model, and run predictions on new samples.
- **Alerting:** Logs suspicious events and can surface notifications during monitoring.

### Building and Running on Ubuntu

```bash
cd Ubuntu
make
./virus_scan
```

For the advanced monitoring executable:

```bash
gcc task4_moniter.c alerts.c -o virus_monitor -lnotify
./virus_monitor
```

### Ubuntu Machine Learning Workflow

```bash
python prepare_data.py
python train_model.py
python predict_malicious.py
```

Artifacts already present in the repository include:

- `combined_labeled_dataset.csv`
- `X_train.csv`, `X_test.csv`, `y_train.csv`, `y_test.csv`
- `virus_detection_model.pkl`
- `new_data_check.csv`

For Linux-specific details, see `Ubuntu/README.md`.

## Outputs and Logs

- **Windows**
  - `behavior_analysis.log`: runtime behavioral events after a signature hit
  - GUI alert dialog and console output during detection
- **Ubuntu**
  - `suspicious_activity.log`: suspicious activity log produced by the Linux monitor
  - model and dataset artifacts under `Ubuntu/`

## Practical Notes

- The Windows implementation is strongest as a behavioral follow-up layer after a signature hit: it escalates into process, registry, and filesystem monitoring immediately after detection.
- The Ubuntu implementation is the more ML-heavy branch of the project and includes the complete dataset-preparation and model-training workflow.
- Signature-based detection depends on the quality of the hash database, so behavior monitoring is an important second layer in both branches.
- This project is best viewed as an academic or prototype malware-detection system rather than a production antivirus replacement.
