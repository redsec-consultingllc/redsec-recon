import os
import whois
import requests
import socket
import json
from fpdf import FPDF
from flask import Flask, request, send_file, render_template

# Load SHODAN API key from environment variable
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

app = Flask(__name__)

# ------------------ Recon Logic ------------------

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
    except:
        return {"Error": "WHOIS lookup failed"}

def check_shodan(domain):
    try:
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        return response.json()
    except:
        return {"Error": "Shodan lookup failed"}

def check_leakcheck(email):
    try:
        resp = requests.get(f"https://leakcheck.net/api/public?check={email}")
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"Error": "LeakCheck lookup failed"}
    except:
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
    except:
        return {"Error": "DeHashed request failed"}

def generate_pdf(domain, data):
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "RedSec Recon Risk Report", ln=True, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f"Target Domain: {domain}", ln=True, align='C')
    pdf.ln(10)

    for section, content in data.items():
        # Section Header
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0)
        pdf.cell(0, 10, section, ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.set_text_color(50, 50, 50)

        if isinstance(content, dict):
            for key, value in content.items():
                value_str = str(value).replace('\n', ' ')
                pdf.multi_cell(0, 8, f"  • {key}: {value_str}", border=0)
        elif isinstance(content, list):
            for i, item in enumerate(content, start=1):
                pdf.multi_cell(0, 8, f"  [{i}] {json.dumps(item, indent=2)}", border=0)
        else:
            pdf.multi_cell(0, 8, f"  {str(content)}", border=0)

        pdf.ln(6)

    os.makedirs("output", exist_ok=True)
    output_path = f"output/RedSec-Recon-{domain}.pdf"
    pdf.output(output_path)
    return output_path


# ------------------ Flask Routes ------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain')
    email = request.form.get('email')

    results = {
        "WHOIS Info": get_domain_info(domain),
        "Shodan Results": check_shodan(domain),
        "LeakCheck Results": check_leakcheck(email),
        "DeHashed Results": check_dehashed(email)
    }

    pdf_path = generate_pdf(domain, results)
    return send_file(pdf_path, as_attachment=True)

# ------------------ Run App ------------------

if __name__ == '__main__':
    app.run(debug=True)
