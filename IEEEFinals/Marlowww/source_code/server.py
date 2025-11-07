#!/usr/bin/env python3

import http.server
import socketserver
import subprocess
import os
import sys
import io
import urllib.parse
import cgi

CHAL_PY = os.environ.get("CHAL_PY", "/srv/domato/chal.py")
PORT = int(os.environ.get("PORT", "13370"))
TIMEOUT = int(os.environ.get("CHAL_TIMEOUT", "10"))
MAX_BODY = int(os.environ.get("MAX_BODY", str(128 * 1024)))  # 128KB default

HTML_FORM = b"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>domato HTTP wrapper</title></head>
<body>
  <h1>Submit domato payload</h1>
  <form method="post" action="/submit" enctype="application/x-www-form-urlencoded">
    <textarea name="payload" rows="20" cols="80" placeholder="Paste payload here..."></textarea><br>
    <input type="submit" value="Send">
  </form>
  <p>Note: Payload must include a trailing line exactly: &lt;EOF&gt;</p>
</body>
</html>
"""

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "DomatoHTTP/0.3"

    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _extract_payload(self, content_type, body_bytes):
        
        if not body_bytes:
            return b""

        if content_type is None:
            payload = body_bytes
        else:
            ct = content_type.split(";")[0].strip().lower()

            if ct == "application/x-www-form-urlencoded":
                try:
                    s = body_bytes.decode("utf-8", errors="replace")
                    qs = urllib.parse.parse_qs(s, keep_blank_values=True)
                    if "payload" in qs:
                        payload = qs["payload"][0].encode("utf-8")
                    else:
                        
                        if s.startswith("payload="):
                            payload = urllib.parse.unquote_plus(s[len("payload="):]).encode("utf-8")
                        else:
                            payload = body_bytes
                except Exception:
                    payload = body_bytes

            elif ct.startswith("multipart/form-data"):
                try:
                    fp = io.BytesIO(body_bytes)
                    env = {"REQUEST_METHOD":"POST"}
                    fs = cgi.FieldStorage(fp=fp, environ=env, headers=self.headers, keep_blank_values=True)
                    if "payload" in fs:
                        field = fs["payload"]
                        if field.file:
                            payload = field.file.read()
                        else:
                            payload = field.value.encode("utf-8")
                    else:
                        payload = body_bytes
                except Exception:
                    payload = body_bytes

            else:
                
                payload = body_bytes

        
        payload = payload.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        return payload

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == "/":
            self._send(200, HTML_FORM)
        else:
            self._send(404, "<h1>Not found</h1>")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path != "/submit":
            self._send(404, "<h1>Not found</h1>")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0

        if content_length > MAX_BODY:
            self._send(413, "<h1>Payload too large</h1>")
            return

        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type", "")

        payload_bytes = self._extract_payload(content_type, body)

        
        preview = payload_bytes[:400].decode("utf-8", errors="replace")
        print(f"[DomatoHTTP] Received payload {len(payload_bytes)} bytes; preview:\n{preview}\n----")

        
        try:
            proc = subprocess.run(
                ["python3", CHAL_PY],
                input=payload_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT
            )
        except subprocess.TimeoutExpired:
            self._send(504, "<h1>Execution timed out</h1>")
            return
        except FileNotFoundError:
            self._send(500, f"<h1>chal.py not found at {CHAL_PY}</h1>")
            return
        except Exception as e:
            self._send(500, f"<h1>Execution error</h1><pre>{e}</pre>")
            return

        out = (proc.stdout or b"") + (proc.stderr or b"")
        self._send(200, out, content_type="text/html; charset=utf-8")

    def log_message(self, format, *args):
        sys.stdout.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))

def main():
    class ThreadingServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    try:
        with ThreadingServer(("", PORT), Handler) as httpd:
            print(f"Listening on 0.0.0.0:{PORT} -> forwarding to {CHAL_PY}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down")
    except Exception as e:
        print("Server error:", e)

if __name__ == "__main__":
    main()