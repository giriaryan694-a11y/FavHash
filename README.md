# 🎯 FavHash – Favicon Hash OSINT Tool

**A clean, accurate favicon hashing tool for OSINT, Red Teaming, and Threat Intelligence.**
**Made by Aryan Giri**

FavHash extracts a website’s favicon and generates multiple forensic hashes:

* **MD5**
* **SHA‑256 / SHA‑1 / MD5** (selectable)
* **MMH3 (Shodan-compatible)**

These hashes allow you to correlate infrastructure across the internet through:
Shodan, FOFA, Zoomeye, Censys, SecurityTrails, and more.

Favicons are widely reused — and this becomes a powerful fingerprinting method.

---

## 🚀 Features

✔ **Accurate MMH3 hashing (Shodan-compatible)**
✔ **MD5, SHA1, SHA256 support**
✔ **Fetch favicon from URL**
✔ **Hash local favicon files**
✔ **Auto-detect common favicon paths**
✔ **Correct Base64 encoding for MMH3**
✔ **Color output with optional `--no-color`**
✔ **Custom ASCII banner (pyfiglet)**
✔ **Clean error handling**
✔ **Save downloaded favicon**
✔ **OSINT correlation query generator** (Shodan, FOFA, Zoomeye, Censys)

This tool is fully **client-side** (no external API calls).

---

## 📦 Installation

Install required dependencies:

```bash
pip install requests mmh3 pyfiglet termcolor colorama
```

Clone or download the project:

```bash
git clone https://github.com/giriaryan694-a11y/FavHash
cd FavHash
```

Run:

```bash
python3 favhash.py --url http://example.com
```

---

## 🛠 Usage

### ▶ Hash favicon from a URL

```bash
python3 favhash.py -u http://testphp.vulnweb.com
```

### ▶ Hash a local favicon file

```bash
python3 favhash.py -f favicon.ico
```

### ▶ Save extracted favicon

```bash
python3 favhash.py -u http://example.com --save icon.ico
```

### ▶ Select hashing algorithm

```bash
python3 favhash.py -u example.com -a sha256
python3 favhash.py -u example.com -a md5
python3 favhash.py -u example.com -a sha1
```

### ▶ Disable color

```bash
python3 favhash.py --no-color -u example.com
```

---

## 📊 Example Output

```
    _________ _    ____  _____   _____ __  __
   / ____/   | |  / / / / /   | / ___// / / /
  / /_  / /| | | / / /_/ / /| | \__ \/ /_/ /
 / __/ / ___ | |/ / __  / ___ |___/ / __  /
/_/   /_/  |_|___/_/ /_/_/  |_/____/_/ /_/

Made by Aryan Giri

[*] Fetching favicon from URL…
MD5 : f17ce23e8c286df713aa992dbbdaeef2
MMH3: 1474949501

┌── OSINT Correlation ──────────────────────────────────────┐
│ Shodan     : http.favicon.hash:1474949501                                 │
│ FOFA MD5   : icon_md5="f17ce23e8c286df713aa992dbbdaeef2"                  │
│ FOFA Hash  : icon_hash="1474949501"                                       │
│ Zoomeye    : iconhash:"f17ce23e8c286df713aa992dbbdaeef2"                  │
│ Censys MD5 : services.http.response.favicon.md5:f17ce23e8c286df713aa992dbb│ef2
└─────────────────────────────────────────────────────────────┘
```

---

## 🧠 Why Favicon Hashing Works

Web frameworks, CMSes, dashboards, login portals, malware panels, SaaS products—
often reuse the **same favicon** across all deployments.

This means:

* Same software
* Same developer
* Same hosting provider
* Same organization
* Same cluster or infrastructure

By hashing a favicon, you can track all servers using it.

This is one of the most **underrated OSINT fingerprinting methods**.

---

## 🌐 Quick OSINT Queries

### 🔎 Shodan

```
http.favicon.hash:<mmh3_hash>
```

### 🔎 FOFA

```
icon_md5="<md5>"
icon_hash="<mmh3_hash>"
```

### 🔎 Zoomeye

```
iconhash:"<md5>"
```

### 🔎 Censys

```
services.http.response.favicon.md5:<md5>
```

---

## 👨‍💻 Credits

**Developed By:** *Aryan Giri*
Specialized in Cybersecurity, Red Teaming & OSINT Development.

---

## 🛡 Disclaimer

This tool is built strictly for:

* Education
* Security research
* OSINT investigations
* Authorized penetration testing

**Do not use it on systems you do NOT have permission to test.**

---

## ⭐ Support the Project

If you like this tool:
✅ Give it a **star** ⭐ on GitHub
✅ Share it with fellow OSINT analysts and bug bounty hunters
