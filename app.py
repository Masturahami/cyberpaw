from flask import Flask, render_template, request, jsonify
import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import socket
import ipaddress
import os

# ------------------------------
# Load VirusTotal API Key
# ------------------------------
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("VirusTotal API key not set. Please set VT_API_KEY as environment variable.")

# ------------------------------
# Flask app
# ------------------------------
app = Flask(__name__)

# ------------------------------
# CyberPaw messages
# ------------------------------
def cyberpaw_message(result_type):
    messages = {
        "safe": "Purr-fect! This link looks safe 🐾 But always stay alert.",
        "suspicious": "Hmm… my whiskers are twitching. Something feels off. Be careful!",
        "dangerous": "Claws out! 🚨 This link is dangerous. Do NOT click it!"
    }
    return messages.get(result_type, "I couldn't figure that one out. Be extra careful!")

# ------------------------------
# Helper functions
# ------------------------------
def is_valid_url(link):
    try:
        parsed = urlparse(link)
        return parsed.scheme in ["http", "https"] and parsed.netloc
    except:
        return False

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except:
        return True

def is_strange_domain(domain):
    return re.search(r"(login|secure|update|verify|account)[.-]", domain)

# ------------------------------
# VirusTotal URL scanning function
# ------------------------------
def virustotal_scan_url(link):
    headers = {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Step 1: Submit URL
    try:
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": link},
            timeout=10
        )
        if submit_resp.status_code != 200:
            return None

        analysis_id = submit_resp.json()["data"]["id"]

        # Step 2: Get analysis result
        analysis_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        if analysis_resp.status_code != 200:
            return None

        stats = analysis_resp.json()["data"]["attributes"]["stats"]
        return stats
    except requests.exceptions.RequestException:
        return None

# ------------------------------
# Main link scanner
# ------------------------------
def check_link(link):
    if not is_valid_url(link):
        return "suspicious"

    parsed = urlparse(link)

    if is_private_ip(parsed.hostname):
        return "dangerous"

    if parsed.scheme != "https":
        return "suspicious"

    try:
        headers = {"User-Agent": "CyberPAW-Link-Scanner/1.2"}
        response = requests.get(link, timeout=5, headers=headers, allow_redirects=True)

        if response.status_code >= 400:
            return "suspicious"

        original_domain = parsed.netloc.lower()
        final_domain = urlparse(response.url).netloc.lower()

        if original_domain != final_domain:
            return "suspicious"

        if is_strange_domain(final_domain):
            return "suspicious"

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.lower() if soup.title and soup.title.string else ""
        meta_desc = soup.find("meta", attrs={"name": "description"})
        desc_text = meta_desc["content"].lower() if meta_desc and meta_desc.get("content") else ""
        body_text = soup.get_text(separator=" ").lower()[:3000]
        scan_text = f"{title} {desc_text} {body_text}"

        if re.search(r"(enter your password|verify your identity|security alert|unauthorized login)", scan_text):
            return "dangerous"
        if re.search(r"(claim your prize|you won|urgent action|limited offer)", scan_text):
            return "suspicious"

        # ------------------------------
        # VirusTotal check
        # ------------------------------
        vt_stats = virustotal_scan_url(link)
        if vt_stats:
            if vt_stats.get("malicious", 0) > 0:
                return "dangerous"
            if vt_stats.get("suspicious", 0) > 0:
                return "suspicious"

        return "safe"

    except requests.exceptions.RequestException:
        return "suspicious"

# ------------------------------
# Routes
# ------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    link = data.get("link", "").strip()

    result_type = check_link(link)
    message = cyberpaw_message(result_type)

    return jsonify({
        "type": result_type,
        "message": message
    })

# ------------------------------
# Run app
# ------------------------------
if __name__ == "__main__":
    app.run()
