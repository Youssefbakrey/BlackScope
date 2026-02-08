import sys, socket, ssl, json, time, re, hashlib, argparse, threading
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from datetime import datetime, timezone
# ================= CONFIG =================
DEFAULT_THREADS = 50
STEALTH_THREADS = 15
DEEP_THREADS = 90

TIMEOUT = 3
BASE_RATE_LIMIT = 0.15
RETRIES = 2

IDOR_KEYWORDS = [
    "/users","/user","/accounts","/account",
    "/profile","/profiles",
    "/orders","/order",
    "/documents","/document",
    "/files","/file","/download"
]

IDOR_PARAMS = [
    "id","user_id","uid","account_id",
    "order_id","file","doc","invoice"
]

# --- Open Redirect ---
REDIRECT_PARAMS = [
    "redirect","redirect_uri","redirect_url",
    "next","url","return","continue","dest"
]

# --- Sensitive Info Disclosure ---
SENSITIVE_REGEX = {
    "JWT": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Internal IP": r"\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))",
    "AWS Key": r"AKIA[0-9A-Z]{16}"
}


TOP_PORTS = [
    # --- Core Network / Auth ---
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    80,     # HTTP
    81,     # Alt Admin
    110,    # POP3
    143,    # IMAP
    443,    # HTTPS
    445,    # SMB
    587,    # SMTP TLS
    993,    # IMAPS
    995,    # POP3S

    # --- Databases (🔥 HIGH VALUE) ---
    1433,   # MSSQL
    1521,   # Oracle
    2049,   # NFS
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    11211,  # Memcached
    27017,  # MongoDB

    # --- Web / Admin / Dashboards ---
    3000,   # Node / React
    5000,   # Flask / .NET
    5601,   # Kibana
    5984,   # CouchDB
    7474,   # Neo4j
    8000,   # Dev servers
    8080,   # HTTP-alt
    8443,   # HTTPS-alt
    8888,   # Admin / Debug
    9000,   # SonarQube
    9200,   # Elasticsearch
    15672,  # RabbitMQ

    # --- Hosting Panels ---
    2082,   # cPanel
    2083,   # cPanel SSL
    2086,   # WHM
    2087,   # WHM SSL
    10000,  # Webmin

    # --- Cloud / Containers / DevOps ---
    2375,   # Docker (NO AUTH!)
    2376,   # Docker TLS
    6443,   # Kubernetes API
    10250,  # Kubelet
    9090,   # Prometheus
    9092,   # Kafka

    # --- Debug / Exotic ---
    4444,   # Debug shells
    50000   # SAP
]


FULL_PORT_RANGE = range(1, 1025)

BASE_HTTP_PATHS = [
    # --- Admin / Control Panels ---
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin-panel",
    "/dashboard",
    "/control",
    "/controlpanel",
    "/cp",
    "/cpanel",
    "/manage",
    "/management",
    "/manager",
    "/administrator",
    "/sysadmin",
    "/root",
    "/superuser",

    # --- Authentication / Account ---
    "/login",
    "/logout",
    "/signin",
    "/signup",
    "/register",
    "/auth",
    "/auth/login",
    "/auth/token",
    "/oauth",
    "/oauth2",
    "/sso",
    "/session",
    "/sessions",
    "/me",
    "/profile",
    "/account",
    "/accounts",
    "/user",
    "/users",

    # --- API / Swagger / GraphQL ---
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/internal",
    "/api/private",
    "/api/admin",
    "/api/docs",
    "/openapi",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/v3/api-docs",
    "/v1/swagger",
    "/v2/swagger",
    "/graphql",
    "/graphiql",
    "/playground",

    # --- Debug / Test / Dev ---
    "/debug",
    "/debugger",
    "/test",
    "/tests",
    "/testing",
    "/dev",
    "/dev-api",
    "/staging",
    "/qa",
    "/sandbox",
    "/internal",
    "/_debug",

    # --- Config / Secrets / Backups (HIGH VALUE) ---
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.git/config",
    "/.gitignore",
    "/.svn",
    "/config",
    "/config.php",
    "/config.json",
    "/appsettings.json",
    "/settings.json",
    "/secrets.json",
    "/credentials",
    "/backup",
    "/backup.zip",
    "/backup.tar",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/database.sql",

    # --- Files / Uploads / Storage ---
    "/uploads",
    "/upload",
    "/files",
    "/file",
    "/storage",
    "/tmp",
    "/temp",
    "/media",
    "/assets",
    "/private",
    "/download",
    "/downloads",

    # --- Framework / Platform Specific ---
    # Laravel
    "/artisan",
    "/storage/logs/laravel.log",
    "/_ignition/execute-solution",

    # Spring Boot
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/configprops",

    # Django
    "/__debug__/",

    # PHP
    "/phpinfo.php",
    "/info.php",
    "/test.php",

    # --- Security / Misc ---
    "/.well-known",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml"
]

API_CONTEXT_PATHS = [
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/docs",
    "/v1/swagger",
    "/v2/swagger"
]

SUB_WORDLIST = [
    # --- Common / Default ---
    "www","api","app","web","site","home",

    # --- Dev / Test / Staging ---
    "dev","dev1","dev2",
    "test","test1","test2",
    "qa","uat",
    "stage","staging","preprod","prod","production",

    # --- Admin / Internal ---
    "admin","administrator","admins",
    "internal","intranet","private",
    "portal","panel","console","dashboard",
    "manage","management","sys","sysadmin",

    # --- Auth / Identity ---
    "auth","login","sso","oauth","id","identity","iam",

    # --- API / Services ---
    "api","api1","api2","api3",
    "rest","graphql","service","services","backend","bff",

    # --- Mobile / Clients ---
    "mobile","m","android","ios","client","clients",

    # --- Cloud / Infra ---
    "cdn","static","assets","files","storage",
    "img","images","media",
    "lb","edge","proxy","gw","gateway",

    # --- Data / Monitoring ---
    "db","database","sql","mongo","redis",
    "logs","log","monitor","metrics","status","health",

    # --- CI/CD / DevOps ---
    "ci","cd","jenkins","git","gitlab","github",
    "build","deploy","release",

    # --- Experimental / Misc ---
    "beta","alpha","preview","demo","sandbox",
    "old","new","legacy","v1","v2","v3"
]

HEADERS = {
    # --- Browser Fingerprint ---
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",

    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "application/json;q=0.8,*/*;q=0.7",

    "Accept-Language": "en-US,en;q=0.9",

    "Accept-Encoding": "gzip, deflate",

    # --- Connection Handling ---
    "Connection": "close",

    # --- Caching / Proxy Behavior ---
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",

    # --- Security / Recon Hints ---
    "Upgrade-Insecure-Requests": "1"
}


requests.packages.urllib3.disable_warnings()

# ================= GLOBALS =================
RESULTS = {
    "target": "",
    "scan_time": "",
    "dns": {},
    "hosts": {},
    "findings": [],
    "errors": []
}

SEEN = set()
THREADS = DEFAULT_THREADS
VERBOSE = False
RATE_LIMIT = BASE_RATE_LIMIT
LOCK = threading.Lock()

# ================= ARGUMENTS =================
def parse_args():
    p = argparse.ArgumentParser(description="ReconX v8.2 Advanced Recon Framework")
    p.add_argument("target")

    p.add_argument("--dns", action="store_true")
    p.add_argument("--subs", action="store_true")
    p.add_argument("--ports", action="store_true")
    p.add_argument("--fast-ports", action="store_true")
    p.add_argument("--http", action="store_true")
    p.add_argument("--paths", action="store_true")
    p.add_argument("--cors", action="store_true")
    p.add_argument("--ssl", action="store_true")
    p.add_argument("--all", action="store_true")
    p.add_argument("--idor", action="store_true", help="Enable IDOR indicators")
    p.add_argument("--open-redirect", action="store_true", help="Enable Open Redirect indicators")
    p.add_argument("--secrets", action="store_true", help="Enable Sensitive Info detection")
    p.add_argument("--host-header", action="store_true", help="Enable Host/Header injection checks")


    p.add_argument("--stealth", action="store_true")
    p.add_argument("--deep", action="store_true")
    p.add_argument("--verbose", action="store_true")

    return p.parse_args()

# ================= UTILS =================
def debug(msg):
    if VERBOSE:
        print(f"[debug] {msg}")

def log_error(ctx, err):
    with LOCK:
        RESULTS["errors"].append({
            "context": ctx,
            "error": str(err)
        })

def adaptive_sleep(status):
    global RATE_LIMIT
    if status in [429, 403]:
        RATE_LIMIT = min(RATE_LIMIT + 0.2, 1.5)
    else:
        RATE_LIMIT = max(BASE_RATE_LIMIT, RATE_LIMIT - 0.05)
    time.sleep(RATE_LIMIT)

def log_finding(host, issue, severity):
    key = hashlib.md5(f"{host}|{issue}".encode()).hexdigest()
    if key in SEEN:
        return
    SEEN.add(key)
    RESULTS["findings"].append({
        "host": host,
        "issue": issue,
        "severity": severity,
        "time": datetime.utcnow().isoformat()
    })

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()
# ================= EXTRA DETECTION =================
def idor_indicators(url, r):
    for k in IDOR_KEYWORDS:
        if k in url and r.status_code == 200:
            return "Potential IDOR (path)"
    for p in IDOR_PARAMS:
        if f"{p}=" in url and r.status_code == 200:
            return f"Potential IDOR parameter: {p}"
    return None

def open_redirect_indicators(url, r):
    for p in REDIRECT_PARAMS:
        if f"{p}=" in url:
            if r.headers.get("Location","").startswith("http"):
                return "Possible Open Redirect"
    return None

def sensitive_info_disclosure(r):
    for name,rx in SENSITIVE_REGEX.items():
        if re.search(rx, r.text):
            return f"Sensitive data exposed: {name}"
    return None

def host_header_injection(base):
    try:
        evil = "evil.com"
        r = requests.get(
            base,
            headers={**HEADERS,"Host":evil,"X-Forwarded-Host":evil},
            verify=False,timeout=6
        )
        if evil in r.text or evil in str(r.headers):
            return "Possible Host Header Injection"
    except:
        pass
    return None
# ================= PROFILES =================
def apply_profile(args):
    global THREADS, VERBOSE, RATE_LIMIT
    if args.stealth:
        THREADS = STEALTH_THREADS
        RATE_LIMIT = 0.4
    elif args.deep:
        THREADS = DEEP_THREADS
        RATE_LIMIT = 0.05
    VERBOSE = args.verbose

# ================= DNS =================
def dns_lookup(domain):
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        RESULTS["dns"]["A"] = ips
    except Exception as e:
        log_error("dns", e)
        RESULTS["dns"]["A"] = []

# ================= SUBDOMAINS =================
def wildcard_check(domain):
    try:
        socket.gethostbyname(f"wildcard-test-{int(time.time())}.{domain}")
        return True
    except:
        return False

def find_subdomains(domain):
    subs = set()
    wildcard = wildcard_check(domain)

    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15
        )
        for e in r.json():
            for n in e.get("name_value","").split("\n"):
                if n.endswith(domain):
                    subs.add(n.strip())
    except Exception as e:
        log_error("crt.sh", e)

    for w in SUB_WORDLIST:
        s = f"{w}.{domain}"
        try:
            socket.gethostbyname(s)
            subs.add(s)
        except:
            pass

    if wildcard:
        log_finding(domain,"Wildcard DNS detected","info")

    return sorted(subs)

# ================= PORT & SERVICE SCAN =================
def grab_banner(sock):
    try:
        sock.send(b"\r\n")
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return ""

def scan_port(host, port):
    for _ in range(RETRIES):
        try:
            with socket.socket() as s:
                s.settimeout(TIMEOUT)
                if s.connect_ex((host, port)) == 0:
                    banner = grab_banner(s)
                    return port, banner
        except Exception as e:
            pass
    return None

def run_port_scan(host, ports):
    found = {}
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = [ex.submit(scan_port, host, p) for p in ports]
        for f in as_completed(futures):
            r = f.result()
            if r:
                port, banner = r
                found[port] = banner
    return found

# ================= HTTP =================
def extract_title(html):
    m = re.search(r"<title>(.*?)</title>", html, re.I|re.S)
    return m.group(1).strip() if m else ""

def cors_probe(url):
    issues = []
    origins = ["https://evil.com", "null"]
    for o in origins:
        try:
            r = requests.get(
                url,
                headers={**HEADERS, "Origin": o},
                verify=False, timeout=6
            )
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acc = r.headers.get("Access-Control-Allow-Credentials","")
            if (acao == "*" or acao == o) and acc.lower() == "true":
                issues.append(f"Misconfigured CORS ({o})")
            adaptive_sleep(r.status_code)
        except:
            pass
    return issues or None

def ssl_info(host):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(4)
            s.connect((host,443))
            cert = s.getpeercert()
            info["expires"] = cert.get("notAfter")
            info["issuer"] = cert.get("issuer")
            info["subject"] = cert.get("subject")
            proto = s.version()
            if proto and proto < "TLSv1.2":
                info["weak_tls"] = proto
            if cert.get("issuer") == cert.get("subject"):
                info["self_signed"] = True
    except Exception as e:
        log_error("ssl", e)
    return info or None

def http_probe(host, args):
    results = {}
    for scheme in ["http","https"]:
        base = f"{scheme}://{host}"
        try:
            r = requests.get(base, headers=HEADERS, verify=False, timeout=6)
            baseline = requests.get(
                base + f"/404-{time.time()}",
                verify=False, timeout=6
            )
        except:
            continue

        base_title = extract_title(baseline.text)
        base_len = len(baseline.content)

        info = {
            "status": r.status_code,
            "title": extract_title(r.text),
            "length": len(r.content),
            "headers": dict(r.headers),
            "paths": []
        }

        if args.cors:
            info["cors"] = cors_probe(base)

        if args.ssl and scheme == "https":
            info["ssl"] = ssl_info(host)

        if args.paths:
            paths = BASE_HTTP_PATHS[:]
            if "api" in host or "application/json" in r.headers.get("Content-Type",""):
                paths += API_CONTEXT_PATHS

            for p in paths:
                try:
                    pr = requests.get(base+p, verify=False, timeout=6)
                    title_sim = similarity(
                        extract_title(pr.text), base_title
                    )
                    if (
                        pr.status_code < 500 and
                        abs(len(pr.content) - base_len) > 120 and
                        title_sim < 0.85
                    ):
                        info["paths"].append({
                            "path": p,
                            "status": pr.status_code
                        })
                        if p in ["/.env","/.git/config","/backup.zip"]:
                            log_finding(host,f"Sensitive file exposed: {p}","high")
                    adaptive_sleep(pr.status_code)
                except:
                    pass

        results[scheme] = info
        adaptive_sleep(r.status_code)

    return results

# ================= CORRELATION =================
def correlate(host, ports, http):
    risk = 0

    for p,b in ports.items():
        if p in [3306,5432,6379]:
            log_finding(host,f"Database port exposed: {p}","high")
            risk += 3
        if b:
            log_finding(host,f"Service banner leaked on {p}: {b[:50]}","low")
            risk += 1

    for scheme,info in http.items():
        for p in info.get("paths",[]):
            if "swagger" in p["path"]:
                log_finding(host,"Swagger exposed","medium")
                risk += 2
            if "admin" in p["path"] and p["status"] == 200:
                log_finding(host,"Admin panel accessible","high")
                risk += 3

        if info.get("cors"):
            log_finding(host,"Insecure CORS configuration","medium")
            risk += 2

        ssl_i = info.get("ssl")
        if ssl_i:
            if ssl_i.get("weak_tls"):
                log_finding(host,"Weak TLS version","low")
                risk += 1
            if ssl_i.get("self_signed"):
                log_finding(host,"Self-signed SSL certificate","low")
                risk += 1

    return risk

# ================= MAIN =================
def main():
    args = parse_args()
    apply_profile(args)

    domain = args.target
    RESULTS["target"] = domain
    RESULTS["scan_time"] = datetime.now(timezone.utc).isoformat()

    print(f"\n ReconX v8.2 scanning {domain}\n")

    if args.all or args.dns:
        dns_lookup(domain)

    subs = []
    if args.all or args.subs:
        subs = find_subdomains(domain)

    hosts = [domain] + subs

    for h in hosts:
        print(f"[+] {h}")
        ports = {}
        http = {}

        if args.all or args.fast_ports:
            ports = run_port_scan(h, TOP_PORTS)

        if args.all or args.ports:
            ports = run_port_scan(h, FULL_PORT_RANGE)

        if args.all or args.http:
            http = http_probe(h, args)

        risk = correlate(h, ports, http)

        RESULTS["hosts"][h] = {
            "ports": ports,
            "http": http,
            "risk_score": risk
        }

    with open("recon_results.json","w") as f:
        json.dump(RESULTS,f,indent=4)

    print("\n✅ Recon Finished → recon_results.json")

if __name__ == "__main__":
    main()
