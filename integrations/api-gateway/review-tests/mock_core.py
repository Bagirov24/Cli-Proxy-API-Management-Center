"""Synthetic Core for review CI. Never uses real keys, OAuth or Railway."""
import json
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNTS = Counter()
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        return  # Never log request bodies, headers or credentials.

    def json_response(self, status, data):
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/__stats":
            with LOCK:
                snapshot = {"hits": sum(COUNTS.values()), "paths": dict(COUNTS)}
            return self.json_response(200, snapshot)
        with LOCK:
            COUNTS[self.path] += 1
        if self.path == "/v1/models":
            return self.json_response(200, {"object": "list", "data": []})
        return self.json_response(404, {"error": "mock route not found"})

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 0:
            raw = self.rfile.read(min(size, 1024 * 1024))
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                return self.json_response(400, {"error": "invalid mock JSON"})
        else:
            payload = {}

        with LOCK:
            COUNTS[self.path] += 1

        if self.path == "/v1/responses":
            return self.json_response(200, {"id": "resp_synthetic", "output": []})
        if self.path != "/v1/chat/completions":
            return self.json_response(404, {"error": "mock route not found"})

        if payload.get("stream") is True:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'data: {"choices":[{"delta":{"content":"A"}}]}\n\n')
            self.wfile.flush()
            time.sleep(0.30)
            self.wfile.write(b'data: {"choices":[{"delta":{"content":"B"}}]}\n\n')
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            return

        return self.json_response(200, {
            "id": "chatcmpl_synthetic",
            "choices": [{"message": {"role": "assistant", "content": "OK"}}],
        })


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8317), Handler).serve_forever()
