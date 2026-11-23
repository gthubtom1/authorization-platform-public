"""Public deployment identity; contains no credentials or administrator data."""
import hashlib
import hmac
from django.conf import settings


def _source_hash():
    digest=hashlib.sha256()
    for directory in ('directsite','files','templates','static','deploy'):
        for path in sorted((settings.BASE_DIR/directory).rglob('*')):
            if path.is_file() and path.suffix in {'.py','.html','.js','.css','.sh','.example'} and '__pycache__' not in path.parts:
                digest.update(path.relative_to(settings.BASE_DIR).as_posix().encode())
                digest.update(b'\0');digest.update(path.read_bytes());digest.update(b'\0')
    return digest.hexdigest()


# Evaluated once per service process, so old workers cannot report new code.
SOURCE_SHA256=_source_hash()


def identity():
    return {'status':'ok','application':'direct-link-site','source_sha256':SOURCE_SHA256,
            'instance':hmac.new(settings.SECRET_KEY.encode(),b'direct-link-health-instance-v1',hashlib.sha256).hexdigest()}
