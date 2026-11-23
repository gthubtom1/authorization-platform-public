import os
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
os.chdir(root)
os.environ.setdefault('DL_DEBUG', '1')
os.environ.setdefault('DL_DATA_DIR', str(root / 'data' / 'local'))
if '--create-admin' in sys.argv:
    subprocess.run([sys.executable, 'manage.py', 'migrate', '--noinput'], check=True)
    subprocess.run([sys.executable, 'manage.py', 'createsuperuser'], check=True)
else:
    subprocess.run([sys.executable, 'manage.py', 'migrate', '--noinput'], check=True)
    print('本地后台：http://127.0.0.1:8780/manage/（关闭进程后停止）', flush=True)
    subprocess.run([sys.executable, 'manage.py', 'runserver', '127.0.0.1:8780', '--noreload'], check=True)
