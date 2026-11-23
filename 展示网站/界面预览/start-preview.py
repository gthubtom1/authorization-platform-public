"""Read-only local design preview. No Django or database changes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, unquote
import mimetypes

ROOT = Path(__file__).resolve().parent
STATIC = ROOT.parent / 'static'

class Preview(BaseHTTPRequestHandler):
    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path.startswith('/static/'):
            base, relative = STATIC, path[len('/static/'):]
        else:
            base, relative = ROOT, path.lstrip('/') or 'index.html'
        target = (base / relative).resolve()
        if not target.is_relative_to(base) or not target.is_file() or target.suffix not in {'.html', '.css', '.js', '.json', '.webp', '.svg', '.ttf', '.png'}:
            self.send_error(404)
            return
        data = target.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', mimetypes.guess_type(target)[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self'; font-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'")
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *_):
        pass

if __name__ == '__main__':
    print('Design preview: http://127.0.0.1:8790/', flush=True)
    ThreadingHTTPServer(('127.0.0.1',8790),Preview).serve_forever()
