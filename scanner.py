import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def scan_site(url):
    if not url.startswith('http'):
        url = 'https://' + url
        
    score = 100
    findings = {
        "score": 100,
        "ssl": "Secure",
        "ssl_days_left": "Unknown",
        "headers": "Checked",
        "tech": "Unknown",
        "vulnerabilities": [],
        "missing_headers": []
    }

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # 1. SECURITY HEADER AUDIT & TECH DETECTION
    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "SentinelAudit/3.0"})
        findings["tech"] = res.headers.get('Server', 'Protected Server')
        
        headers_to_check = {
            'Content-Security-Policy': 'CSP Header missing (Risk: XSS)',
            'Strict-Transport-Security': 'HSTS Header missing (Risk: MitM)',
            'X-Frame-Options': 'X-Frame Header missing (Risk: Clickjacking)'
        }
        for h, risk in headers_to_check.items():
            if h not in res.headers:
                score -= 10
                findings["missing_headers"].append(risk)
    except Exception as e:
        score -= 20
        findings["tech"] = "Unreachable Node"

    # 2. SSL EXPIRY CHECK
    if hostname:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expire_str = cert.get('notAfter')
                    expire_date = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.utcnow()).days
                    findings["ssl_days_left"] = f"{days_left} Days Remaining"
                    if days_left < 15:
                        score -= 15
                        findings["vulnerabilities"].append("SSL Certificate is close to expiration.")
        except:
            score -= 30
            findings["ssl"] = "Insecure/No SSL Certificate found"
            findings["vulnerabilities"].append("Target missing strong HTTPS validation.")

    # 3. VULNERABILITY TESTING (SQLi & XSS Payload Fuzzing)
    xss_payload = "<script>alert(1)</script>"
    sqli_payload = "' OR '1'='1"
    
    try:
        test_url_xss = f"{url}?search={xss_payload}"
        test_url_sqli = f"{url}?id={sqli_payload}"
        
        r_xss = requests.get(test_url_xss, timeout=5)
        if xss_payload in r_xss.text:
            score -= 20
            findings["vulnerabilities"].append("Potential Cross-Site Scripting (XSS) vulnerability detected.")
            
        r_sqli = requests.get(test_url_sqli, timeout=5)
        if "sql syntax" in r_sqli.text.lower() or "mysql" in r_sqli.text.lower():
            score -= 25
            findings["vulnerabilities"].append("Potential SQL Injection flaw detected via parameter injection.")
    except:
        pass

    findings["score"] = max(score, 5)
    return findings
