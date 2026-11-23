#!/usr/bin/env bash
set -euo pipefail
# Install/update this independent project only; never run the parent installer here.
site=/opt/direct-link-site
if [[ "${EUID}" != 0 || "$(pwd -P)" != "$site" ]]; then
  echo 'Run as root from /opt/direct-link-site after deployment authorization.' >&2; exit 1
fi
test -f .env || { echo 'Prepare .env first, using an independent site secret.' >&2; exit 1; }
command -v nginx >/dev/null
command -v python3 >/dev/null
python3 - <<'PY'
import pathlib,re
text=pathlib.Path('.env').read_text()
values={}
for line in text.splitlines():
    if line and not line.startswith('#') and '=' in line:
        k,v=line.split('=',1);values[k]=v
if values.get('DL_DEBUG')!='0' or values.get('DL_USE_ACCEL','0')!='0':
    raise SystemExit('Production requires DL_DEBUG=0 and verified streaming path DL_USE_ACCEL=0.')
if len(values.get('DL_SECRET_KEY',''))<50 or 'replace-with' in values.get('DL_SECRET_KEY',''):
    raise SystemExit('Set an independent secret; never reuse authorization platform keys.')
domain=values.get('DL_HOSTS','')
if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',domain) or domain.endswith('.example.com'):
    raise SystemExit('Set one real DL_HOSTS domain.')
if values.get('DL_DATA_DIR')!='/opt/direct-link-site/data' or values.get('DL_TRUST_PROXY')!='1' or values.get('DL_CSRF_ORIGINS')!='https://'+domain:
    raise SystemExit('Set canonical data directory, proxy trust and CSRF origin.')
if not pathlib.Path('/etc/letsencrypt/live',domain,'fullchain.pem').is_file():
    raise SystemExit('Prepare a valid certificate for this domain first; do not overwrite another site.')
template=pathlib.Path('deploy/nginx.conf.example').read_text()
pathlib.Path('/etc/nginx/sites-available/direct-link-site.conf').write_text(template.replace('__DOMAIN__',domain).replace('__TLS_CERT_NAME__',domain))
PY
id directlink >/dev/null 2>&1 || useradd --system --home-dir "$site" --shell /usr/sbin/nologin directlink
mkdir -p data
chown directlink:directlink data
chmod 700 data
chown root:directlink .env
chmod 640 .env
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
set -a
# .env is root-controlled, reviewed deployment configuration.
source .env
set +a
runuser -u directlink --preserve-environment -- .venv/bin/python manage.py migrate --noinput
runuser -u directlink --preserve-environment -- .venv/bin/python manage.py check --deploy
.venv/bin/python manage.py collectstatic --noinput
install -m 644 deploy/direct-link-site.service.example /etc/systemd/system/direct-link-site.service
install -m 644 deploy/direct-link-maintain.service.example /etc/systemd/system/direct-link-maintain.service
install -m 644 deploy/direct-link-maintain.timer.example /etc/systemd/system/direct-link-maintain.timer
ln -sfn /etc/nginx/sites-available/direct-link-site.conf /etc/nginx/sites-enabled/direct-link-site.conf
nginx -t
systemctl daemon-reload
systemctl enable --now direct-link-site.service direct-link-maintain.timer
systemctl restart direct-link-site.service
systemctl reload nginx
.venv/bin/python deploy/verify-site.py
