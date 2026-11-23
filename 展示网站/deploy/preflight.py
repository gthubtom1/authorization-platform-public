"""Fail before backup, shutdown or migration if this host cannot run the site."""
import json
from pathlib import Path
import re
import subprocess

root=Path(__file__).resolve().parents[1]
values={line.split('=',1)[0]:line.split('=',1)[1] for line in (root/'.env').read_text().splitlines() if line and not line.startswith('#') and '=' in line}
domain=values.get('SITE_DOMAIN','')
if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',domain) or domain.endswith('.example.com'):
    raise SystemExit('Set one confirmed real SITE_DOMAIN.')
if values.get('SITE_HOSTS')!=domain or values.get('SITE_CSRF_ORIGINS')!='https://'+domain or len(values.get('SITE_SECRET_KEY',''))<50 or 'replace-with' in values.get('SITE_SECRET_KEY',''):
    raise SystemExit('Set exact hosts/origin and an independent secret.')
if not (Path('/etc/letsencrypt/live')/domain/'fullchain.pem').is_file():
    raise SystemExit('Prepare this domain certificate first; preserve other sites.')
config=json.loads(subprocess.check_output(['docker','compose','config','--format','json'],text=True))
ports=config['services']['web'].get('ports',[])
if len(ports)!=1 or str(ports[0].get('published'))!='18082' or ports[0].get('target')!=8080 or ports[0].get('host_ip')!='127.0.0.1' or config['services']['app'].get('ports'):
    raise SystemExit('Only the loopback web port 18082 may be published.')
listeners=subprocess.check_output(['ss','-lnt'],text=True)
if re.search(r':18082\s',listeners):
    existing=subprocess.run(['docker','compose','port','web','8080'],capture_output=True,text=True)
    if existing.returncode or existing.stdout.strip()!='127.0.0.1:18082':
        raise SystemExit('Port 18082 belongs to another service; no update performed.')
nginx=subprocess.run(['nginx','-T'],capture_output=True,text=True,check=True)
own=Path('/etc/nginx/sites-available/software-showcase.conf')
for source,body in re.findall(r'# configuration file ([^\n]+):\n(.*?)(?=# configuration file |\Z)',nginx.stdout,re.S):
    if Path(source).resolve()==own.resolve():continue
    for names in re.findall(r'\bserver_name\s+([^;]+);',body):
        if domain in names.split():raise SystemExit('Domain is already served by another Nginx site.')
print(domain)
