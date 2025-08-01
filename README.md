# 🕵️‍♂️ archive_urls

**archive_urls** is a Python OSINT tool that collects archived and public URLs for a given domain using multiple public sources:

- 📦 Wayback Machine  
- 🔍 urlscan.io  
- 🛰️ Common Crawl  
- 🌐 AlienVault OTX  

Useful for bug bounty hunters, penetration testers, and recon specialists. It supports deduplication, output formatting (HTML/CSV/TXT), and grouping similar URLs.

---

## 📌 Features

- 🔗 Collect URLs from 4 major OSINT sources
- 🧠 Optional deduplication with `--unique`
- 🤝 Group similar URLs using `--group-similar`
- 💾 Save results in HTML, CSV, and TXT
- 📅 Timestamped filenames per domain
- 🔍 Highlights URLs with query parameters
- 💻 Simple CLI-based tool (no API keys needed)

---

## 💻 Installation

```bash
git clone https://github.com/yourusername/archive_urls.git
cd archive_urls
pip install requests, beautifulsoup, tldextract

** Python 3.7 or later is required.**


**python archive_urls.py <target-domain> --format=html,csv,txt [--unique] [--group-similar]**
python archive_urls.py example.com --format=html
python archive_urls.py example.com --format=csv,txt --unique
python archive_urls.py testsite.org --format=html,csv --group-similar

| Argument          | Description                                                    |
| ----------------- | -------------------------------------------------------------- |
| `<target-domain>` | Domain to search archived URLs for                             |
| `--format=`       | Comma-separated formats: `html`, `csv`, `txt`                  |
| `--unique`        | (Optional) Removes exact duplicate URLs                        |
| `--group-similar` | (Optional) Groups URLs with same path but different parameters |



🙏 Credits
Wayback Machine
urlscan.io
Common Crawl
AlienVault OTX




