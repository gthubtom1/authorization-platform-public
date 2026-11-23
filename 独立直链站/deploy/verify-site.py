"""Verify the installed service and local HTTPS routing. Never follows redirects."""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
os.environ.setdefault('DJANGO_SETTINGS_MODULE','directsite.settings')


def require_response(status, body, expected):
    if status != 200 or json.loads(body) != expected:
        raise RuntimeError('Wrong status, application, source version or instance')


def verify():
    import django
    django.setup()
    from files.deployment import identity
    expected=identity();domain=os.environ['DL_HOSTS']
    def command(*args):return subprocess.check_output(args,text=True).strip()
    if command('systemctl','is-active','direct-link-site.service')!='active':raise RuntimeError('Service inactive')
    props=dict(line.split('=',1) for line in command('systemctl','show','direct-link-site.service','-p','MainPID','-p','WorkingDirectory','-p','User','-p','ExecStart').splitlines())
    if props['WorkingDirectory']!='/opt/direct-link-site' or props['User']!='directlink' or '/opt/direct-link-site/.venv/bin/gunicorn' not in props['ExecStart'] or '--bind 127.0.0.1:18081' not in props['ExecStart']:
        raise RuntimeError('Wrong service definition')
    pid=int(props['MainPID'])
    listeners=command('ss','-lntp')
    if pid<=0 or not any('127.0.0.1:18081' in line and f'pid={pid},' in line for line in listeners.splitlines()):raise RuntimeError('Expected local listener is not owned by this service')
    direct=http.client.HTTPConnection('127.0.0.1',18081,timeout=10)
    try:
        direct.request('GET','/healthz/',headers={'Host':domain,'X-Forwarded-Proto':'https'})
        response=direct.getresponse();require_response(response.status,response.read(),expected)
    finally:direct.close()
    local=http.client.HTTPSConnection(domain,timeout=15)
    local._create_connection=lambda address,timeout,*args:socket.create_connection(('127.0.0.1',443),timeout)
    try:
        local.request('GET','/healthz/')
        response=local.getresponse();require_response(response.status,response.read(),expected)
    finally:local.close()
    print('VERIFY_OK: local service, source, instance, Host/SNI and TLS matched')


if __name__=='__main__':verify()
