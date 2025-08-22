import os
import whois
import requests
import socket
import json
from fpdf import FPDF
from flask import Flask, request, send_file, render_template
from datetime import datetime

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

app = Flask(__name__)

# ---------- Logging ----------
import logging
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

# ---------- Recon Functions ----------

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": str(w.creation_date),
            "Expiration Date": str(w.expiration_date),
            "Name Servers": w.name_servers
        }
    except Exception as e:
        app.logger.error(f"WHOIS lookup failed: {e}")
        return {"Error": "WHOIS lookup failed"}

def check_shodan(domain):
    try:
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        return response.json()
    except Exception as e:
        app.logger.error(f"Shodan lookup failed: {e}")
        return {"Error": "Shodan lookup failed"}

def check_leakcheck(email):
    try:
        resp = requests.get(f"https://leakcheck.net/api/public?check={email}")
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"Error": "LeakCheck lookup failed"}
    except Exception as e:
        app.logger.error(f"LeakCheck error: {e}")
        return {"Error": "LeakCheck API error"}

def check_dehashed(email):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        url = f"https://www.dehashed.com/search?query={email}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return {"Info": "Results available. Visit DeHashed.com manually for more details."}
        else:
            return {"Error": "DeHashed lookup failed or blocked"}
    except Exception as e:
        app.logger.error(f"DeHashed error: {e}")
        return {"Error": "DeHashed request failed"}

def generate_pdf(domain, data):
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "RedSec Recon Risk Report", ln=True, align='C')

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Target: {domain}", ln=True, align='C')
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)

    for section, content in data.items():
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0)
        pdf.cell(0, 10, section, ln=True)

        pdf.set_font("Arial", size=10)
        pdf.set_text_color(50, 50, 50)

        if isinstance(content, dict):
            for k, v in content.items():
                k = str(k).replace('\n', ' ')
                v = str(v).replace('\n', ' ')
                pdf.multi_cell(0, 8, f"   - {k}: {v}")
        elif isinstance(content, list):
            for i, item in enumerate(content, 1):
                line = json.dumps(item, indent=2) if isinstance(item, (dict, list)) else str(item)
                pdf.multi_cell(0, 8, f"   [{i}] {line}")
        else:
            pdf.multi_cell(0, 8, f"   {str(content)}")

        pdf.ln(5)

    os.makedirs("output", exist_ok=True)
    output_path = f"output/RedSec-Recon-{domain}.pdf"
    pdf.output(output_path)
    return output_path


# ---------- Routes ----------

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        domain = request.form['domain']
        email = request.form['email']
        app.logger.info(f"Scanning {domain} and {email}")
        report_data = {
            "WHOIS Info": get_domain_info(domain),
            "Shodan Results": check_shodan(domain),
            "LeakCheck Results": check_leakcheck(email),
            "DeHashed Results": check_dehashed(email)
        }
        pdf_path = generate_pdf(domain, report_data)
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        app.logger.error("Unexpected error during scan", exc_info=True)
        return render_template('index.html', error="Internal error occurred. Check logs.")
