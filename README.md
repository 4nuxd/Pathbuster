# Dynamic Path Traversal Tester

This project is a **path traversal testing toolkit** designed for web application security assessments. It provides a systematic way to test endpoints for **directory traversal / path traversal vulnerabilities** using both built-in payloads and custom-generated ones.

---

## 📂 Project Structure

- **`enhanced_script.py`**  
  The main testing script. Sends crafted GET requests with payloads injected into URL parameters and checks for signs of sensitive file disclosure (like `/etc/passwd`).

- **`payload_generation.py`**  
  A helper script that dynamically generates payloads from a set of traversal sequences and file targets defined in `all_payloads.txt`. It outputs a Python list of payload tuples into `new_techniques.txt`.

- **`all_payloads.txt`**  
  Contains target filenames and paths you want to attempt reading (e.g., `/etc/passwd`, `.git/config`, `robots.txt`). You can extend this list to suit your assessment.

- **`new_techniques.txt`**  
  The generated payloads file that `enhanced_script.py` can load when the `--cp` flag is used. This file is produced by `payload_generation.py`.

---

## ⚡ Features

- ✅ **Built-in payload techniques** for common traversal methods:
  - Relative paths (`../`)
  - Double/URL-encoded sequences
  - Unicode/overlong encodings
  - Null-byte terminators
  - Base-directory bypass tricks

- ✅ **Custom payload support** via `--cp new_techniques.txt`  
  Payloads are defined in Python tuple format, e.g.:
  ```python
  ("NT01", "Custom traversal test", lambda: "../../../etc/passwd"),
  ("NT02", "Double encoded trick", lambda: "%252e%252e%252fetc/passwd"),
