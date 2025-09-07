
````markdown
# Pathbuster 

A **path traversal testing toolkit** designed for web application security assessments. It provides a systematic way to test endpoints for **directory traversal / path traversal vulnerabilities** using both built-in payloads and custom-generated ones.

---

## 📂 Project Structure

- **`main.py`**  
  The main testing script. Sends crafted GET requests with payloads injected into URL parameters and checks for signs of sensitive file disclosure (like `/etc/passwd`).

- **`payload_generation.py`**  
  A helper script that dynamically generates payloads from a set of traversal sequences and file targets defined in `all_payloads.txt`. It outputs a Python list of payload tuples into `new_techniques.txt`.

- **`all_payloads.txt`**  
  Contains target filenames and paths you want to attempt reading (e.g., `/etc/passwd`, `.git/config`, `robots.txt`). You can extend this list to suit your assessment.

- **`new_techniques.txt`**  
  The generated payloads file that `main.py` can load when the `--cp` flag is used. This file is produced by `payload_generation.py`.

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
````

* ✅ **Target parameter auto-detection**
  If you don’t specify `-p`, the script will parse query parameters from the URL. Defaults to `filename`.

* ✅ **Multiple URL support** via `--list urls.txt`.

* ✅ **Verbose mode** for detailed request/response information.

* ✅ **Full response output** with `--full` when a payload matches (e.g., shows entire `/etc/passwd` contents if accessible).

* ✅ **Delay, timeout, redirect, and TLS options** for better control during testing.

---

## 🚀 Usage

### 1. Run with built-in payloads

```bash
python main.py -u "http://target.com/download?file=test.txt"
```

### 2. Run with custom payloads

```bash
python main.py -u "http://target.com/download?file=test.txt" --cp new_techniques.txt
```

### 3. Show full responses on successful matches

```bash
python main.py -u "http://target.com/download?file=test.txt" --full
```

### 4. Test multiple URLs from a file

```bash
python main.py --list urls.txt
```

---

## ⚙️ Options

| Flag           | Description                                                        |
| -------------- | ------------------------------------------------------------------ |
| `-u / --url`   | Target endpoint (e.g., `http://localhost:8080/download`)           |
| `-p / --param` | Parameter name to inject (default: all query params or `filename`) |
| `--list`       | File containing a list of URLs to test                             |
| `--cp`         | Load custom payloads from `new_techniques.txt`                     |
| `--delay`      | Delay between requests (default: `0.2s`)                           |
| `--timeout`    | Request timeout (default: `10s`)                                   |
| `--insecure`   | Skip TLS certificate verification                                  |
| `--follow`     | Follow HTTP redirects                                              |
| `--verbose`    | Detailed output for each request                                   |
| `--full`       | Print full response if a leak is detected                          |

---

## 🛠 How It Works

1. **Payload Generation**

   * Run `payload_generation.py` to combine traversal sequences with files in `all_payloads.txt`.
   * Example:

     ```
     ../../../../etc/passwd
     %2e%2e%2f%2e%2e%2fetc/passwd
     ....//....//etc/passwd
     ```
   * The results are formatted as Python tuples and saved in `new_techniques.txt`.

2. **Enhanced Testing Script**

   * Run `main.py` with `--cp new_techniques.txt`.
   * It loads both built-in and custom payloads, injects them into the target URL, and inspects responses.
   * The script specifically looks for `/etc/passwd` patterns (usernames, UID/GID, `/bin/` paths).

3. **Detection**

   * If `/etc/passwd`-like content is found, the script marks it as a **possible leak**.
   * Use `--full` to dump the entire response body.

---

## 📝 Changes Made in This Version

* Added `--cp` flag to load payloads from `new_techniques.txt` (Python tuple format).
* Implemented `ast.literal_eval` parsing for safer custom payload loading.
* Added `--full` flag to display complete response bodies when leaks are detected.
* Improved error handling for invalid custom payloads.
* Informational message when custom payloads are successfully loaded.
* Cleaned and documented code for easier extension.

---

## ⚠️ Disclaimer

This tool is for **educational and authorized penetration testing purposes only**.
Do **not** use it against systems without explicit permission. Unauthorized use may violate the law.

---

```
