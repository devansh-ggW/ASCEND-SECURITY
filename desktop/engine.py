import hashlib, os, re, shutil, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

APP_DIR = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ASCEND'
QUARANTINE = APP_DIR / 'Quarantine'
QUARANTINE.mkdir(parents=True, exist_ok=True)

@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    points: int = 0

@dataclass
class Result:
    target: str
    score: int
    verdict: str
    findings: list
    sha256: str = ''
    size: int = 0
    file_type: str = ''
    elapsed_ms: int = 0

def verdict(score): return 'HIGH RISK' if score >= 70 else 'SUSPICIOUS' if score >= 35 else 'LOW SIGNAL'
def sha256_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def scan_file(path_text):
    start=time.perf_counter(); path=Path(path_text).expanduser().resolve()
    if not path.is_file(): return Result(str(path),100,'HIGH RISK',[Finding('danger','File unavailable','The selected path is not a regular file.',100)])
    st=path.stat(); name=path.name; low=name.lower(); findings=[]; score=0
    with open(path,'rb') as f: head=f.read(4096)
    if re.search(r'\.(exe|msi|dll|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|wsf|wsh|jar)$',low,re.I): score+=18; findings.append(Finding('review','Executable/script extension','This file can execute code when opened by a compatible component.',18))
    if re.search(r'\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|zip|rar)\.(exe|scr|bat|cmd|js|vbs|ps1|hta)$',low,re.I): score+=45; findings.append(Finding('danger','Suspicious double extension','The filename is disguised as a document/image but ends in an executable type.',45))
    if any(ord(c)<32 for c in name): score+=25; findings.append(Finding('danger','Control character in filename','Non-printing characters can make filenames misleading.',25))
    if len(name)>120: score+=6; findings.append(Finding('review','Very long filename','The important part of the extension may be hard to notice.',6))
    if head.startswith(b'MZ'):
        score+=18; findings.append(Finding('review','Windows PE signature','The MZ signature is commonly used by Windows executables.',18))
        if b'PE\x00\x00' in head: findings.append(Finding('info','PE header found','A Portable Executable header was found in the first 4 KB.'))
    for marker,title,points in [(b'powershell -enc','Encoded PowerShell marker',18),(b'rundll32','rundll32 reference',10),(b'regsvr32','regsvr32 reference',10),(b'mshta','mshta reference',10),(b'wscript','Windows Script Host reference',8)]:
        if marker in head.lower(): score+=points; findings.append(Finding('review',title,'An execution-related string was found by static inspection.',points))
    try: digest=sha256_file(path) if st.st_size<=1024*1024*1024 else ''
    except OSError: digest=''
    if not findings: findings.append(Finding('safe','No obvious static indicators','No common filename/header red flags were found. This does not prove the file is safe.'))
    return Result(str(path),min(score,100),verdict(score),findings,digest,st.st_size,path.suffix.upper() or 'UNKNOWN',round((time.perf_counter()-start)*1000))

def scan_folder(path_text,limit=300):
    root=Path(path_text).expanduser().resolve(); paths=[]
    if root.is_file(): paths=[root]
    elif root.is_dir(): paths=[p for p in root.rglob('*') if p.is_file()][:limit]
    return [scan_file(str(p)) for p in paths]

def analyze_url(raw):
    raw=raw.strip(); f=[]; score=0
    try:
        u=urlparse(raw)
        if u.scheme not in ('http','https') or not u.netloc: raise ValueError
    except ValueError: return Result(raw,90,'HIGH RISK',[Finding('danger','Invalid URL','Not a normal HTTP/HTTPS URL.',90)])
    host=(u.hostname or '').lower()
    tests=[(u.scheme!='https',18,'No HTTPS','The URL does not use HTTPS.'),(bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',host)),28,'Raw IP hostname','An IP address is used instead of a normal domain.'),('xn--' in host,25,'Punycode hostname','Verify the domain carefully.'),(bool(u.username or u.password),30,'Embedded user information','Credentials appear before the hostname.'),(bool(u.port and u.port not in (80,443)),15,'Unusual port',f'Port {u.port} is in use.'),(len(host.split('.'))>=4,10,'Many subdomains','Several hostname levels are present.'),(bool(re.search(r'bit\.ly|tinyurl\.com|t\.co|ow\.ly|is\.gd|cutt\.ly',host,re.I)),18,'URL shortener','The visible URL may hide the final destination.'),(bool(re.search(r'[\u200b-\u200f\u2060\ufeff]',raw)),24,'Invisible Unicode','Invisible Unicode characters were detected.'),(len(raw)>180,8,'Long URL','The URL is unusually long.'),(bool(re.search(r'[?&](redirect|url|next|return|continue)=',u.query,re.I)),10,'Redirect parameter','A redirect-style parameter is present.'),(bool(re.search(r'login|verify|secure|account|wallet|password|support|claim|reward|refund|invoice',raw,re.I)),12,'Sensitive-action language','Account, payment or reward language appears in the URL.')]
    for ok,pts,title,detail in tests:
        if ok: score+=pts; f.append(Finding('danger' if pts>=25 else 'review',title,detail,pts))
    if not f: f.append(Finding('safe','No obvious URL indicators','No common structural red flags were found.'))
    return Result(raw,min(score,100),verdict(score),f,file_type=host)

def analyze_message(text):
    rules=[(r'urgent|immediately|act now|last chance',20,'Urgency or countdown language'),(r'otp|one[- ]time password|verification code|passcode',25,'Verification-code request'),(r'password|login|credential|pin|cvv|card number|bank details',28,'Sensitive credential/payment detail'),(r'refund|payment|invoice|fee|transfer|send money|pay now',20,'Payment pressure'),(r'won|winner|prize|reward|gift card|lottery|free money',22,'Prize/reward bait'),(r'suspend|blocked|locked|deactivated|legal action|police',22,'Threat of account loss/consequences'),(r'anydesk|teamviewer|remote access|screen share|install this app',30,'Remote-access language'),(r'https?://\S+',8,'Clickable web link')]
    f=[]; score=0
    for pat,pts,title in rules:
        if re.search(pat,text,re.I): score+=pts; f.append(Finding('danger' if pts>=25 else 'review',title,'A common social-engineering signal matched this message.',pts))
    if re.search(r'[\u200b-\u200f\u2060\ufeff]',text): score+=20; f.append(Finding('danger','Invisible Unicode','Invisible Unicode characters were detected.',20))
    if not f: f.append(Finding('safe','No common scam signals','No common social-engineering patterns were detected.'))
    return Result('Message',min(score,100),verdict(score),f)

def list_processes():
    import csv,io
    try: out=subprocess.check_output(['tasklist','/fo','csv','/nh'],text=True,errors='replace',timeout=5)
    except Exception: return []
    return [{'name':r[0],'pid':r[1],'memory':r[4]} for r in csv.reader(io.StringIO(out)) if len(r)>=5]

def list_connections():
    try: return subprocess.check_output(['netstat','-ano'],text=True,errors='replace',timeout=5).splitlines()
    except Exception: return []

def quarantine(path_text):
    src=Path(path_text).expanduser().resolve()
    if not src.is_file(): raise ValueError('Only regular files can be quarantined.')
    dest=QUARANTINE/f'{time.strftime("%Y%m%d-%H%M%S")}_{src.name}'
    n=1
    while dest.exists(): dest=QUARANTINE/f'{time.strftime("%Y%m%d-%H%M%S")}_{n}_{src.name}'; n+=1
    shutil.move(str(src),str(dest)); return dest
