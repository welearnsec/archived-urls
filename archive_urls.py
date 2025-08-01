import argparse
import requests
import re
import csv
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
from collections import defaultdict
from datetime import datetime

HEADERS = {'User-Agent': 'Mozilla/5.0'}

# --- Fetch functions ---

def fetch_waybackurls(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            return r.text.strip().splitlines()
    except:
        pass
    return []

def fetch_alienvault(domain):
    urls = []
    page = 1
    while True:
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?page={page}", headers=HEADERS, timeout=15)
            if r.status_code != 200:
                break
            data = r.json()
            urls.extend([entry['url'] for entry in data.get('url_list', [])])
            if not data.get('has_next', False):
                break
            page += 1
        except:
            break
    return urls

def fetch_urlscan(domain):
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", headers=HEADERS, timeout=15)
        results = r.json().get('results', [])
        return [r['page']['url'] for r in results if 'page' in r]
    except:
        return []

def fetch_commoncrawl(domain):
    try:
        idx_res = requests.get('https://index.commoncrawl.org/collinfo.json', timeout=10)
        indexes = idx_res.json()
        urls = set()
        for idx in indexes[-2:]:  # last 2 indexes for freshness
            cdx_api = idx['cdx-api']
            res = requests.get(f"{cdx_api}?url=*.{domain}/*&output=json", timeout=15)
            for line in res.text.strip().splitlines():
                match = re.search(r'"url":"(.*?)"', line)
                if match:
                    url = match.group(1).replace('\\u002f', '/')
                    urls.add(url)
        return list(urls)
    except:
        return []

def fetch_urlhaus(domain):
    try:
        r = requests.get(f"https://urlhaus.abuse.ch/browse.php?search={domain}", headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        urls = []
        for a in soup.select('table a[href^="http"]'):
            href = a.get('href', '')
            if domain in href:
                urls.append(href)
        return urls
    except:
        return []

def fetch_hunter(domain):
    # Placeholder - Hunter.io requires API key; skipping real calls
    return []

# --- URL utils ---

def normalize_url(url):
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/')
        qs = sorted(parse_qsl(parsed.query))
        query = urlencode(qs)
        normalized = urlunparse((scheme, netloc, path, '', query, ''))
        return normalized
    except:
        return url

def highlight_params(url):
    parsed = urlparse(url)
    if not parsed.query:
        return url
    base = url[:url.find('?')+1]
    parts = []
    for k, v in parse_qsl(parsed.query):
        parts.append(f'<span style="color:red;font-weight:bold">{k}={v}</span>')
    return base + '&'.join(parts)

def group_similar(urls):
    groups = defaultdict(list)
    for url in urls:
        try:
            p = urlparse(url)
            base = f"{p.scheme}://{p.netloc}{p.path}"
            groups[base].append(url)
        except:
            continue
    grouped_list = []
    for base, variants in groups.items():
        if len(variants) > 1:
            grouped_list.append(f"{base} ({len(variants)} variants)")
        else:
            grouped_list.append(base)
    return grouped_list

# --- Output functions ---

def save_html(urls, filename):
    html = f"<html><head><title>Archived URLs</title></head><body><h2>Archived URLs ({len(urls)})</h2><ul>"
    for u in urls:
        html += f"<li><a href='{u}' target='_blank'>{highlight_params(u)}</a></li>"
    html += "</ul></body></html>"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

def save_csv(urls, filename):
    with open(filename, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['URL'])
        for u in urls:
            writer.writerow([u])

def save_txt(urls, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(urls))

# --- Main CLI ---

def main():
    parser = argparse.ArgumentParser(description="Archive URLs extractor with multiple sources and output formats")
    parser.add_argument('domain', help='Target domain (e.g. example.com)')
    parser.add_argument('--format', default='html', help='Output format(s), comma separated (html,csv,txt)')
    parser.add_argument('--unique-only', action='store_true', help='Normalize and deduplicate URLs')
    parser.add_argument('--group-similar', action='store_true', help='Group URLs by base path and count variants')
    args = parser.parse_args()

    domain = args.domain.strip()
    formats = [f.strip().lower() for f in args.format.split(',')]

    print(f"[*] Gathering URLs for domain: {domain}")

    urls = []
    print("[*] Fetching from Wayback Machine...")
    urls.extend(fetch_waybackurls(domain))
    print("[*] Fetching from AlienVault OTX...")
    urls.extend(fetch_alienvault(domain))
    print("[*] Fetching from urlscan.io...")
    urls.extend(fetch_urlscan(domain))
    print("[*] Fetching from Common Crawl...")
    urls.extend(fetch_commoncrawl(domain))
    print("[*] Fetching from URLHaus...")
    urls.extend(fetch_urlhaus(domain))
    print("[*] Fetching from Hunter.io (skipped - API required)...")

    print(f"[+] Collected {len(urls)} URLs before processing")

    if args.unique_only:
        urls = list({normalize_url(u) for u in urls})
        print(f"[+] {len(urls)} unique URLs after normalization")

    if args.group_similar:
        urls = group_similar(urls)
        print(f"[+] Grouped into {len(urls)} base URLs")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"archived_urls_{domain}_{timestamp}"

    if 'html' in formats:
        save_html(urls, base_filename + ".html")
        print(f"[+] Saved HTML to {base_filename}.html")

    if 'csv' in formats:
        save_csv(urls, base_filename + ".csv")
        print(f"[+] Saved CSV to {base_filename}.csv")

    if 'txt' in formats:
        save_txt(urls, base_filename + ".txt")
        print(f"[+] Saved TXT to {base_filename}.txt")

    print("[*] Done.")

if __name__ == '__main__':
    main()
