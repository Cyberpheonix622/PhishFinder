import re
import socket
import ssl
import urllib.parse
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import pandas as pd
import os

TRUSTED_DOMAINS = {"google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com"}
SUSPICIOUS_TLDS = {'ru', 'tk', 'cn', 'ml', 'gq', 'info', 'biz'}
BRAND_KEYWORDS = ["paypal", "ebay", "amazon", "bank", "login", "verify", "secure", "account"]

IP_REGEX = re.compile(r'(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)')
HEX_ENCODED = re.compile(r'%[0-9a-f]{2}', re.IGNORECASE)

def resolve_ip(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except socket.gaierror:
        return 0

def is_suspicious(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()

    if IP_REGEX.match(domain):
        return True, "internal_ip"

    if any(brand in domain and not domain.endswith(f"{brand}.com") for brand in BRAND_KEYWORDS):
        return True, "brand_spoofing"

    if not resolve_ip(domain):
        return True, "dns_failure"

    return False, None

def get_domain_reputation(domain, use_api=False):
    if not use_api:
        return 0
    try:
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
        if not api_key:
            return 0

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishfinder", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"http://{domain}"}]
            }
        }
        response = requests.post(api_url, json=payload, timeout=3)
        return 1 if response.json().get("matches") else 0
    except:
        return 0

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(3)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        issuer = dict(x[0] for x in cert['issuer'])
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_to_expiry = (not_after - datetime.utcnow()).days
        return {
            "ssl_valid": 1,
            "ssl_days_to_expiry": days_to_expiry,
            "ssl_issuer_trusted": 1 if "Let's Encrypt" in issuer.get('O', '') else 0
        }
    except:
        return {"ssl_valid": 0, "ssl_days_to_expiry": 0, "ssl_issuer_trusted": 0}

def get_domain_age(domain):
    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.utcnow() - creation_date).days
        return {
            "domain_age_days": age_days,
            "domain_registered_recently": 1 if age_days < 30 else 0
        }
    except:
        return {"domain_age_days": 0, "domain_registered_recently": 1}

def get_page_behavioral_features(url):
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        return {
            "qty_iframes": len(soup.find_all('iframe')),
            "qty_script_tags": len(soup.find_all('script')),
            "qty_onmouseover": html.count("onmouseover"),
            "qty_eval": html.count("eval(")
        }
    except:
        return {"qty_iframes": 0, "qty_script_tags": 0, "qty_onmouseover": 0, "qty_eval": 0}

def extract_heuristic_features(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    return {
        'internal_ip': 1 if IP_REGEX.match(domain) else 0,
        'suspicious_port': 1 if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443') else 0,
        'hex_encoded': 1 if HEX_ENCODED.search(url) else 0,
        'multiple_subdomains': 1 if domain.count('.') > 3 else 0,
        'brand_in_path': 1 if any(brand in path for brand in BRAND_KEYWORDS) else 0
    }

def extract_statistical_features(url, network_calls=True):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {
        'length_url': len(url),
        'domain_length': len(domain),
        'directory_length': len(path),
        'file_length': len(path.split('/')[-1]),
        'params_length': len(query),
        'qty_params': query.count('&') + 1 if query else 0,
        'tld_present_params': 1 if any(tld in query for tld in ['.com', '.net', '.org']) else 0,
        'domain_in_ip': 1 if re.match(r'(\d{1,3}\.){3}\d{1,3}', domain) else 0,
        'server_client_domain': 1 if 'client' in domain or 'server' in domain else 0,
        'qty_vowels_domain': sum(domain.count(v) for v in 'aeiouAEIOU'),
        'qty_ip_resolved': resolve_ip(domain),
        'tls_ssl_certificate': 1 if url.startswith("https") else 0,
        'url_shortened': 1 if re.search(r"(bit\.ly|goo\.gl|tinyurl\.com)", url) else 0,
        'is_trusted_domain': 1 if domain in TRUSTED_DOMAINS else 0
    }

    if network_calls:
        features.update({
            'domain_in_blacklist': get_domain_reputation(domain),
            **get_ssl_info(domain),
            **get_domain_age(domain),
            **get_page_behavioral_features(url)
        })
    else:
        features.update({
            'domain_in_blacklist': 0,
            'ssl_valid': 0, 'ssl_days_to_expiry': 0, 'ssl_issuer_trusted': 0,
            'domain_age_days': 0, 'domain_registered_recently': 1,
            'qty_iframes': 0, 'qty_script_tags': 0, 'qty_onmouseover': 0, 'qty_eval': 0
        })

    return features

def combine_features(url, network_calls=True):
    stat_features = extract_statistical_features(url, network_calls)
    heuristic_features = extract_heuristic_features(url)
    return pd.DataFrame([{**stat_features, **heuristic_features}])
