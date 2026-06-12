import sqlite3
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

ALLOWED_HOSTS = {"api.trusted-partner.com", "external-service.example.com"}
ALLOWED_SCHEMES = {"https"}
BLOCKED_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8"]

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        if parsed.hostname not in ALLOWED_HOSTS:
            return False
        ip = ipaddress.ip_address(parsed.hostname)
        for blocked in BLOCKED_RANGES:
            if ip in ipaddress.ip_network(blocked):
                return False
        return True
    except:
        return False

@app.route('/api/v1/profile', methods=['GET'])
def get_profile():
    user_input_id = request.args.get('id')
    
    if user_input_id is None:
        return jsonify({"error": "id parameter required"}), 400
    
    conn = sqlite3.connect('app_db.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, email, role FROM users WHERE id = ?", (user_input_id,))
    data = cursor.fetchone()
    conn.close()
    
    if data is None:
        return jsonify({"profile": None}), 404
    
    return jsonify({"profile": data})

@app.route('/api/v1/proxy', methods=['POST'])
def proxy_request():
    target_destination = request.json.get('endpoint')
    
    if not target_destination or not is_safe_url(target_destination):
        return jsonify({"error": "Destination not permitted"}), 400
    
    response = requests.get(target_destination, timeout=10, allow_redirects=False)
    return jsonify({"content": response.text})

if __name__ == '__main__':
    app.run(port=8080)
