import contextlib
import hashlib
import os
import shutil
import threading
import time
from pathlib import Path
from django.conf import settings

_thread_locks = {'write': threading.RLock(), 'rate': threading.RLock()}


def root():
    p = settings.DATA_DIR / 'files'
    p.mkdir(exist_ok=True)
    return p


def blob_path(blob_id):
    return root() / (str(blob_id) + '.bin')


def part_path(upload_id):
    return root() / (str(upload_id) + '.part')


@contextlib.contextmanager
def site_lock(timeout=35, *, namespace='write'):
    if namespace not in _thread_locks:
        raise ValueError('Unknown lock namespace')
    deadline = time.monotonic() + timeout
    thread_lock = _thread_locks[namespace]
    if not thread_lock.acquire(timeout=max(0, timeout)):
        raise Busy('有文件正在处理，请稍后重试。', 503)
    try:
        lock = settings.DATA_DIR / (namespace + '.lock')
        with lock.open('a+b') as f:
            f.seek(0, 2)
            if f.tell() == 0:
                f.write(b'0')
                f.flush()
            while True:
                try:
                    f.seek(0)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, BlockingIOError):
                    if time.monotonic() >= deadline:
                        raise Busy('有文件正在处理，请稍后重试。', 503)
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            try:
                yield
            finally:
                f.seek(0)
                if os.name == 'nt':
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        thread_lock.release()


class Busy(Exception):
    def __init__(self, message, status=400):
        self.message = message
        self.status = status
        super().__init__(message)


def checked_path(path):
    if path.is_symlink() or path.parent.is_symlink() or path.resolve().parent != root().resolve():
        raise Busy('文件路径异常，下载暂不可用。', 503)
    return path


def hash_file(path):
    h = hashlib.sha256()
    with checked_path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def unlink(path):
    try:
        checked_path(path).unlink(missing_ok=True)
        return True
    except PermissionError:
        # Windows open download handles can defer reclaim until maintenance.
        return False


def free_space():
    return shutil.disk_usage(settings.DATA_DIR).free
