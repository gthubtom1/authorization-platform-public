"""Local-only launcher. The runtime and database belong to this subproject."""
import os
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
runtime = root / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
if not runtime.exists():
    subprocess.run([sys.executable, '-m', 'venv', str(root / '.venv')], check=True)
    subprocess.run([str(runtime), '-m', 'pip', 'install', '-r', str(root / 'requirements.txt')], check=True)
env = os.environ.copy()
env['SITE_DEBUG'] = '1'
env.setdefault('SITE_DATA_DIR', str(root / 'data' / 'local'))
env.setdefault('SITE_HOSTS', '127.0.0.1,localhost,[::1]')
subprocess.run([str(runtime), 'manage.py', 'migrate', '--noinput'], cwd=root, env=env, check=True)
if '--create-admin' in sys.argv:
    subprocess.run([str(runtime), 'manage.py', 'createsuperuser'], cwd=root, env=env, check=True)
else:
    subprocess.run([str(runtime), 'manage.py', 'runserver', '127.0.0.1:8770', '--noreload'], cwd=root, env=env, check=True)
