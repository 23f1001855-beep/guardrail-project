
from flask import Flask, request, jsonify
from pathlib import Path
from urllib.parse import urlparse
import requests
import socket
import ipaddress

app = Flask(__name__)

BASE_DIR = Path(__file__).parent.resolve()

SANDBOX = BASE_DIR / "agent-redteam" / "sandbox-8e3404a7db"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}
def read_file(path):
    try:
        # Convert the requested path into an absolute path
        requested = (SANDBOX / path).resolve()

        # Make sure it stays inside the sandbox
        requested.relative_to(SANDBOX)

        # Check if the file exists
        if not requested.exists():
            return {
                "action": "block",
                "reason": "File not found"
            }

        # Read the file
        with open(requested, "r") as file:
            content = file.read()

        return {
            "action": "allow",
            "reason": "Valid sandbox path",
            "result": content
        }

    except ValueError:
        return {
            "action": "block",
            "reason": "Path traversal detected"
        }

    except Exception as e:
        return {
            "action": "block",
            "reason": str(e)
        }
def validate_url(url):
    try:
        parsed = urlparse(url)

        # Only HTTP/HTTPS
        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP/HTTPS URLs are allowed"

        # Block username/password tricks
        if parsed.username or parsed.password:
            return False, "Userinfo not allowed"

        host = parsed.hostname

        if not host:
            return False, "Invalid URL"

        # Allow only exact hosts
        if host not in ALLOWED_HOSTS:
            return False, "Host not allowed"

        # Resolve all IPs
        addresses = socket.getaddrinfo(host, None)

        for addr in addresses:
            ip = ipaddress.ip_address(addr[4][0])

            if (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_reserved or
                ip.is_unspecified
            ):
                return False, f"Blocked IP: {ip}"

        return True, "URL validated"

    except Exception as e:
        return False, str(e)
def fetch_url(url):

    valid, reason = validate_url(url)

    if not valid:
        return {
            "action": "block",
            "reason": reason
        }

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        return {
            "action": "allow",
            "reason": "URL allowed",
            "result": response.text
        }

    except Exception as e:
        return {
            "action": "block",
            "reason": str(e)
        }
@app.route("/", methods=["POST"])
def guardrail():

    data = request.get_json()

    if not data:
        return jsonify({
            "action": "block",
            "reason": "Invalid JSON"
        })

    tool = data.get("tool")
    arguments = data.get("arguments", {})

    if tool == "read_file":

        path = arguments.get("path", "")

        return jsonify(read_file(path))

    elif tool == "fetch_url":

        url = arguments.get("url", "")

        return jsonify(fetch_url(url))

    else:

        return jsonify({
            "action": "block",
            "reason": "Unknown tool"
        })
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )
import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5001)),
        debug=False
    )
