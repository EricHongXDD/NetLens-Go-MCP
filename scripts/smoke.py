#!/usr/bin/env python3
"""Exercise the real binary over stdio MCP plus an explicit local HTTP proxy.

Uses only Python's standard library and temporary local listeners. Run after:
    go build -o bin/netlens ./cmd/netlens
    python3 scripts/smoke.py ./bin/netlens
"""
import argparse
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import urllib.parse


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    count = 0
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            type(self).count += 1
        body = json.dumps({"ok": True, "token": "RESPONSE-SECRET", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=COOKIE-SECRET")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="./bin/netlens")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if not Path(binary).is_file():
        raise SystemExit("Build the binary first: go build -o bin/netlens ./cmd/netlens")
    with tempfile.TemporaryDirectory(prefix="netlens-smoke-") as directory:
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        output = queue.Queue()
        env = dict(os.environ)
        env["NETLENS_TOKEN"] = "smoke-control-token-is-long-enough-123456789"
        with open(Path(directory) / "stderr.log", "w+") as stderr:
            process = subprocess.Popen(
                [binary, "mcp", "--proxy", "127.0.0.1:0", "--control", "127.0.0.1:0",
                 "--data-dir", directory, "--allow-replay", "--allow-rules", "--timeout", "10s"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                text=True, encoding="utf-8", bufsize=1, env=env,
            )
            def read_lines():
                for line in process.stdout:
                    output.put(line)
                output.put(None)
            threading.Thread(target=read_lines, daemon=True).start()
            seq = 0

            def rpc(method, params=None, notification=False):
                nonlocal seq
                message = {"jsonrpc": "2.0", "method": method}
                if params is not None:
                    message["params"] = params
                if not notification:
                    seq += 1
                    message["id"] = seq
                process.stdin.write(json.dumps(message) + "\n")
                process.stdin.flush()
                if notification:
                    return None
                while True:
                    line = output.get(timeout=20)
                    if line is None:
                        raise AssertionError("MCP process closed stdout unexpectedly")
                    response = json.loads(line)  # Detects accidental logging on stdout.
                    if response.get("id") == seq:
                        assert "error" not in response, response
                        return response["result"]

            def tool(name, arguments):
                result = rpc("tools/call", {"name": name, "arguments": arguments})
                assert not result.get("isError"), result
                return result.get("structuredContent") or json.loads(result["content"][0]["text"])

            try:
                initialize = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                  "clientInfo": {"name": "netlens-smoke", "version": "1"}})
                assert initialize["serverInfo"]["name"] == "netlens"
                rpc("notifications/initialized", {}, notification=True)
                assert len(rpc("tools/list", {})["tools"]) == 11
                state = tool("capture_status", {})
                proxy_host, proxy_port = state["proxy_addr"].rsplit(":", 1)
                target = "http://127.0.0.1:%d/check?api_key=QUERY-SECRET" % upstream.server_port
                connection = http.client.HTTPConnection(proxy_host, int(proxy_port), timeout=10)
                connection.request("GET", target, headers={"Authorization": "Bearer HEADER-SECRET"})
                response = connection.getresponse()
                original_body = response.read()
                assert response.status == 200
                assert b"RESPONSE-SECRET" in original_body  # Proxy preserves wire content.
                connection.close()
                # A completed network response can race the final store snapshot;
                # list a bounded number of times, with blocking RPC doing the wait.
                for _ in range(20):
                    flows = tool("flows_list", {"limit": 10})["items"]
                    if flows and flows[0]["completed"]:
                        break
                assert flows and flows[0]["completed"], flows
                flow_id = flows[0]["id"]
                detail = tool("flows_get", {"id": flow_id})
                serialized = json.dumps(detail)
                for secret in ("QUERY-SECRET", "HEADER-SECRET", "RESPONSE-SECRET", "COOKIE-SECRET"):
                    assert secret not in serialized, secret
                replayed = tool("requests_replay", {"flow_id": flow_id, "confirm": True})
                assert replayed["parent_id"] == flow_id and replayed["source"] == "replay"
                assert Origin.count == 2, Origin.count
                tool("capture_configure", {"enabled": False})
                assert tool("capture_status", {})["capture"]["enabled"] is False
                # Local HTTP MCP/control API shares the stdio process and requires a token.
                host, port = state["control_addr"].rsplit(":", 1)
                control = http.client.HTTPConnection(host, int(port), timeout=10)
                control.request("GET", "/api/status")
                unauthorized = control.getresponse()
                assert unauthorized.status == 401
                unauthorized.read()
                control.request("GET", "/api/status", headers={"Authorization": "Bearer " + env["NETLENS_TOKEN"]})
                authorized = control.getresponse()
                assert authorized.status == 200
                assert json.loads(authorized.read())["capture"]["enabled"] is False
                control.close()
                har = tool("flows_export_har", {"limit": 2, "body_limit": 256})
                assert har["log"]["version"] == "1.2"
                cleared = tool("flows_clear", {"confirm": True})
                assert cleared["removed"] == 2
                process.stdin.close()  # Client disconnect must stop both listeners.
                assert process.wait(timeout=10) == 0
                print("PASS: real stdio MCP handshake, 11 tools, proxy capture, redaction, replay, shared control state, auth, HAR and graceful EOF shutdown")
            except Exception:
                stderr.flush()
                stderr.seek(0)
                print(stderr.read())
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        process.wait(timeout=5)
                    if process.poll() is None:
                        process.kill()
                upstream.shutdown()
                upstream.server_close()


if __name__ == "__main__":
    main()
