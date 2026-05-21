import sqlite3
import requests
import ipaddress
import socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# CS-005 fix: exact set of external hostnames this proxy is permitted to reach.
# Update this list to match your actual integration partners.
ALLOWED_HOSTS = {
    "api.trusted-partner.com",
    "external-service.example.com",
}
ALLOWED_SCHEMES = {"https"}

# Private, loopback, and link-local ranges — must never be reachable via proxy.
BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/GCP IMDS
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fd00::/8"),
]


def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        if parsed.hostname not in ALLOWED_HOSTS:
            return False
        # Resolve and check IP to block DNS rebinding attacks.
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if any(ip in net for net in BLOCKED_RANGES):
            return False
        return True
    except Exception:
        return False


# CS-004 fix: parameterised query — input cannot alter query structure.
@app.route('/api/v1/profile', methods=['GET'])
def get_profile():
    user_input_id = request.args.get('id')

    if user_input_id is None:
        return jsonify({"error": "id parameter required"}), 400

    conn = sqlite3.connect('app_db.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, email, role FROM users WHERE id = ?",
        (user_input_id,)
    )
    data = cursor.fetchone()
    conn.close()

    if data is None:
        return jsonify({"profile": None}), 404
    return jsonify({"profile": data})


# CS-005 fix: validate destination against allowlist before proxying.
@app.route('/api/v1/proxy', methods=['POST'])
def proxy_request():
    target_destination = request.json.get('endpoint')

    if not target_destination or not is_safe_url(target_destination):
        return jsonify({"error": "Destination not permitted"}), 400

    response = requests.get(target_destination, timeout=10, allow_redirects=False)
    return jsonify({"content": response.text})


if __name__ == '__main__':
    app.run(port=8080)
