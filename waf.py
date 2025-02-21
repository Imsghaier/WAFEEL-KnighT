from flask import Flask, request, abort
import re
import defusedxml.ElementTree as ET  # Safe XML parsing
from io import StringIO
from pymongo import MongoClient
import requests  # For making HTTP requests

app = Flask(__name__)

# Connect to MongoDB
client = MongoClient('mongodb://mongo:27017/')  # Replace with your MongoDB connection string
db = client.waf_db  # Use the 'waf_db' database
logs = db.logs  # Use the 'logs' collection

# Advanced SQL Injection Detection
def detect_advanced_sql_injection(query_string):
    """
    Detects obfuscated or time-based SQL injection payloads.
    """
    obfuscated_patterns = [
        r"sleep\(\d+\)",  # Time-based SQLi
        r"benchmark\(\d+,\w+\)",  # Time-based SQLi
        r"union\s+select",  # Obfuscated UNION SELECT
        r"[\s\(\)]*select[\s\(\)]*",  # Obfuscated SELECT
        r"[\s\(\)]*from[\s\(\)]*",  # Obfuscated FROM
    ]
    for pattern in obfuscated_patterns:
        if re.search(pattern, query_string, re.IGNORECASE):
            return True
    return False

# Command Injection Detection
def detect_command_injection(input_string):
    """
    Detects system command injection patterns.
    """
    command_patterns = [
        r";\s*\w+",  # Command chaining (e.g., ; rm -rf /)
        r"&\s*\w+",  # Background execution (e.g., & rm -rf /)
        r"\|\s*\w+",  # Piping (e.g., | rm -rf /)
        r"`.*`",  # Backticks (e.g., `rm -rf /`)
        r"\$\s*\(",  # Command substitution (e.g., $(rm -rf /))
    ]
    for pattern in command_patterns:
        if re.search(pattern, input_string):
            return True
    return False

# XPATH Injection Detection
def detect_xpath_injection(input_string):
    """
    Detects malicious XPATH queries.
    """
    xpath_patterns = [
        r"['\"].*or.*['\"]",  # XPATH OR condition (e.g., ' or '1'='1)
        r"['\"].*and.*['\"]",  # XPATH AND condition
        r"['\"].*=\s*['\"]",  # XPATH equality (e.g., '1'='1')
    ]
    for pattern in xpath_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False

# XXE Injection Prevention
def prevent_xxe_injection(xml_input):
    """
    Disables external entity parsing in XML inputs.
    """
    try:
        xml_tree = ET.parse(StringIO(xml_input))  # Safe XML parsing
        return False  # No XXE detected
    except ET.EntitiesForbidden:
        return True  # XXE detected
    except Exception as e:
        return True  # Invalid XML or other errors

# XSS Detection
def detect_xss(input_string):
    """
    Detects common XSS payloads in input strings.
    """
    xss_patterns = [
        r"<script.*?>.*?</script>",  # Script tags
        r"javascript:",  # JavaScript URIs
        r"<.*?on\w+.*?>",  # HTML attributes with event handlers
        r"eval\(.*?\)",  # eval() function
        r"alert\(.*?\)",  # alert() function
        r"document\.cookie",  # Accessing cookies
        r"document\.location",  # Accessing location
        r"window\.location",  # Accessing window location
        r"localStorage",  # Accessing localStorage
        r"sessionStorage"  # Accessing sessionStorage
    ]
    for pattern in xss_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False

# Insert document with XSS detection
def insert_document(collection, document):
    """
    Inserts a document into the specified MongoDB collection after checking for XSS.
    """
    for key, value in document.items():
        if isinstance(value, str) and detect_xss(value):
            raise ValueError("Stored XSS detected")
    collection.insert_one(document)

# Flask Route to Handle Requests
@app.route('/', methods=['GET', 'POST'])
def handle_request():
    query_string = request.query_string.decode('utf-8')
    request_data = request.data.decode('utf-8')
    ip_address = request.remote_addr

    attack_detected = False
    attack_type = ""

    # Advanced SQL Injection Check
    if detect_advanced_sql_injection(query_string):
        attack_detected = True
        attack_type = "Advanced SQL Injection"

    # Command Injection Check
    if detect_command_injection(request_data):
        attack_detected = True
        attack_type = "Command Injection"

    # XPATH Injection Check
    if detect_xpath_injection(request_data):
        attack_detected = True
        attack_type = "XPATH Injection"

    # XXE Injection Check
    if request.headers.get('Content-Type') == 'application/xml':
        if prevent_xxe_injection(request_data):
            attack_detected = True
            attack_type = "XXE Injection"

    # XSS Check
    if detect_xss(query_string) or detect_xss(request_data):
        attack_detected = True
        attack_type = "Cross-Site Scripting (XSS)"

    # Block the request if an attack is detected
    if attack_detected:
        log_request({
            "query_string": query_string,
            "request_data": request_data,
            "ip_address": ip_address,
            "attack_type": attack_type
        })
        abort(403)  # Forbidden

    # Log normal request
    try:
        insert_document(logs, {
            "query_string": query_string,
            "request_data": request_data,
            "ip_address": ip_address,
            "status": "passed"
        })
    except ValueError as e:
        log_request({
            "query_string": query_string,
            "request_data": request_data,
            "ip_address": ip_address,
            "attack_type": "Stored XSS"
        })
        abort(403)  # Forbidden

    # Forward request to WebGoat
    response = requests.get("http://webgoat:8080/WebGoat" + request.path)
    return response.content

# Log request details to MongoDB
def log_request(info):
    """
    Logs request details to MongoDB.
    """
    logs.insert_one(info)  # Insert the log into the 'logs' collection

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response to mitigate DOM-Based XSS.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self';"
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)
