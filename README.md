# BlackScope
Features
 Asset Discovery

DNS resolution & subdomain enumeration

Wildcard DNS detection

High‑value service & admin port scanning

 HTTP & API Recon

Intelligent endpoint & path discovery

Baseline‑aware filtering to reduce false positives

Detection of admin panels, Swagger, debug & internal endpoints

 Advanced IDOR Indicators

Object‑aware ID mutation (numeric & UUID)

Baseline vs modified response comparison

Confidence‑based findings (medium / high)

Non‑intrusive heuristics (no brute force)

 Misconfiguration Detection

Insecure CORS configurations

Sensitive file exposure (.env, .git, backups)

Weak TLS / SSL certificate issues

Host header injection indicators

 Risk Correlation Engine

Cross‑layer analysis (ports + HTTP + SSL)

Automated severity scoring

Prioritized findings for efficient manual testing

 Stealth‑Friendly by Design

Adaptive rate limiting

Multiple scan profiles (stealth / default / deep)

Recon‑only approach (no exploitation)

# Installation :

https://github.com/Youssefbakrey/BlackScope.git

cd blackscope

pip install -r requirements.txt

# Requirements :

Python 3.9+

requests

# Usage

python blackscope.py google.com --all

# Common Options

--dns           DNS resolution

--subs          Subdomain enumeration

--ports         Full port scan

--fast-ports    High‑value ports only

--http          HTTP probing

--paths         Endpoint & path discovery

--cors          CORS checks

--ssl           SSL/TLS analysis

--idor          Context‑aware IDOR indicators

--all           Run full recon

--stealth       Low & slow mode

--deep          Aggressive recon

--verbose       Debug output

Output

All results are saved to:
recon_results.json


Includes:

Discovered hosts & services
HTTP endpoints & API paths
Correlated security findings
Risk scores per host
# Notes 
python blackscope.py google.com --all not https://google.com
