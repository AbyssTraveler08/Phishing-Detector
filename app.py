from flask import Flask, request, jsonify
from collections import defaultdict
from urllib.parse import urlparse
import re
import time
import os

app = Flask(__name__)

# Dictionary to store IP access logs
ip_access_log = defaultdict(list)

# Serve the HTML interface
@app.route('/', methods=['GET'])
def home():
    return open("index.html").read()

# Extract features from the URL
def extract_features(url):
    features = {}
    parsed = urlparse(url)

    # Checks if the domain is an IP address
    features['has_ip'] = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.netloc))

    # Checks if the URL uses HTTPS
    features['has_https'] = parsed.scheme == "https"

    # Checks if the URL contains '@'
    features['has_at_symbol'] = '@' in url

    # Checks URL length
    features['url_length'] = len(url)

    # Counts number of dots in domain
    features['num_dots'] = parsed.netloc.count('.')

    return features

# Basic phishing logic
def is_phishing(features):
    if features['has_ip']:
        return True
    if not features['has_https']:
        return True
    if features['has_at_symbol']:
        return True
    if features['url_length'] > 75:
        return True
    if features['num_dots'] > 3:
        return True
    return False

# Suspicious behavior check
def detect_suspicious_behavior(ip):
    times = ip_access_log[ip]
    now = time.time()
    times = [t for t in times if now - t < 60]  # last 60 seconds
    ip_access_log[ip] = times

    if len(times) > 5:
        return True
    return False

# API endpoint
@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    user_ip = request.remote_addr
    current_time = time.time()
    ip_access_log[user_ip].append(current_time)

    suspicious = detect_suspicious_behavior(user_ip)

    features = extract_features(url)
    result = is_phishing(features)

    response = {
        "url": url,
        "phishing": result,
        "your_ip": user_ip,
        "suspicious_behavior": suspicious,
        "features": features
    }

    if suspicious:
        print(f"⚠️ Suspicious activity detected from IP: {user_ip} ⚠️")

    return jsonify(response)

# Start the app
if __name__ == '__main__':
    app.run(debug=True)
