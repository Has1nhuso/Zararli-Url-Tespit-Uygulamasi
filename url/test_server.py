from __future__ import annotations

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        pages = Path(__file__).parent / "test_pages"
        super().__init__(*args, directory=str(pages), **kwargs)


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8000
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Test server: http://{host}:{port}/safe.html")
    print(f"Test server: http://{host}:{port}/phishy.html")
    httpd.serve_forever()
