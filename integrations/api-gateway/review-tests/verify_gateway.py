"""Synthetic black-box tests for candidate Caddy gateway. No production calls."""
import json
import os
import time
from urllib import request, error

BASE = os.environ.get("GATEWAY_TEST_BASE", "http://127.0.0.1:8080")
CORE = os.environ.get("MOCK_CORE_BASE", "http://127.0.0.1:8317")
KEY = "cpa_" + "a" * 43
REQUEST_SEQ = 0


def call(path, payload=None, headers=None, base=BASE):
    global REQUEST_SEQ
    data = None if payload is None else json.dumps(payload).encode()
    outbound_headers = dict(headers or {})
    if base == BASE and "X-Real-IP" not in outbound_headers:
        REQUEST_SEQ += 1
        outbound_headers["X-Real-IP"] = f"198.51.100.{REQUEST_SEQ}"
    req = request.Request(
        base + path,
        data=data,
        headers=outbound_headers,
        method="POST" if data is not None else "GET",
    )
    try:
        with request.urlopen(req, timeout=15) as rsp:
            return rsp.status, rsp.read(), dict(rsp.headers)
    except error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def hits():
    status, body, _ = call("/__stats", base=CORE)
    assert status == 200, status
    return json.loads(body)["hits"]


def must(path, payload, headers, expected, extra=None):
    before = hits()
    actual, body, hdr = call(path, payload, headers)
    after = hits()
    assert actual == expected, (path, actual, expected, body[:160])
    if extra == "not_forwarded":
        assert before == after, (path, "unexpected Core hit")
    if extra == "forwarded":
        assert after == before + 1, (path, before, after)
    print(f"PASS {path}: HTTP {actual}")
    return body, hdr


def main():
    payload = {"model": "gpt-6-luna", "messages": [{"role":"user","content":"hello"}]}
    good = {"Authorization": "Bearer " + KEY, "Content-Type": "application/json"}
    bad = {"Authorization": "Bearer invalid"}

    must("/healthz", None, {}, 200, "not_forwarded")
    must("/management.html", None, {}, 404, "not_forwarded")
    must("/oauth/callback", None, {}, 404, "not_forwarded")
    must("/v1/embeddings", payload, good, 404, "not_forwarded")
    must("/v1/chat/completions", payload, {}, 401, "not_forwarded")
    must("/v1/chat/completions", payload, bad, 401, "not_forwarded")
    must("/v1/chat/completions", payload, good, 200, "forwarded")
    must("/v1/responses", {"model":"gpt-6-luna","input":"ok"}, good, 200, "forwarded")
    must("/v1/models", None, good, 200, "forwarded")
    must("/v1/models", None, {}, 401, "not_forwarded")
    must("/v1/chat/completions/", payload, good, 404, "not_forwarded")

    # Ensure a genuine streaming response is forwarded.
    before = hits()
    t0 = time.monotonic()
    body, h = must("/v1/chat/completions", {**payload, "stream": True}, good, 200, "forwarded")
    assert b"data: [DONE]" in body, body[:500]
    assert b"data: " in body, body[:500]
    assert "text/event-stream" in h.get("Content-Type", ""), h
    assert time.monotonic() - t0 >= 0.25, "synthetic streamed wait was lost"
    assert hits() == before + 1

    # Separate gateway rate limiting from Core; synthetic key is NOT secret.
    # Two successive requests are allowed in the test configuration, third
    # is rejected with 429 and never reaches the synthetic Core.
    before = hits()
    isolated = {**good, "X-Real-IP": "192.0.2.234"}
    for _ in range(2):
        must("/v1/chat/completions", payload, isolated, 200, "forwarded")
    must("/v1/chat/completions", payload, isolated, 429, "not_forwarded")
    assert hits() == before + 2

    print("ALL GATEWAY REVIEW TESTS PASSED")


if __name__ == "__main__":
    main()
