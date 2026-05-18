import sqlite3
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Category: Injection (SQL) 
# Severity: High (If exposed on an unauthenticated endpoint)
@app.route('/api/v1/profile', methods=['GET'])
def get_profile():
    # Claude Security traces this raw input string direct into the database execution
    user_input_id = request.args.get('id')
    
    conn = sqlite3.connect('app_db.db')
    cursor = conn.cursor()
    
    # Structural query change vulnerability: e.g., ' OR 1=1--
    query = f"SELECT username, email, role FROM users WHERE id = '{user_input_id}'"
    cursor.execute(query)
    data = cursor.fetchone()
    
    return jsonify({"profile": data})

# Category: Path & Network (SSRF)
# Severity: High/Medium (Depends on environment cloud metadata access)
@app.route('/api/v1/proxy', methods=['POST'])
def proxy_request():
    # Input controls the destination completely
    # Triggers on attempts to fetch: http://169.254.169.254/latest/meta-data/
    target_destination = request.json.get('endpoint')
    
    response = requests.get(target_destination)
    return jsonify({"content": response.text})

if __name__ == '__main__':
    app.run(port=8080)
