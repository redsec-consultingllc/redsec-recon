import os
import whois
import requests
import socket
import json
from fpdf import FPDF
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# ---------- Helper Functions ----------

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
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="RedSec Recon Risk Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Target: {domain}", ln=True, align='C')
    pdf.ln(10)

    for section, content in data.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt=section, ln=True)
        pdf.set_font("Arial", size=10)
        if isinstance(content, dict):
            for k, v in content.items():
                pdf.multi_cell(0, 10, f"{k}: {v}")
        elif isinstance(content, list):
            for item in content:
                pdf.multi_cell(0, 10, json.dumps(item, indent=2))
        else:
            pdf.multi_cell(0, 10, str(content))
        pdf.ln(5)

    os.makedirs("output", exist_ok=True)
    output_path = f"output/RedSec-Recon-{domain}.pdf"
    pdf.output(output_path)
    return output_path

# ---------- Run Recon Logic ----------

def run_recon(domain, email):
    report_data = {
        "WHOIS Info": get_domain_info(domain),
        "Shodan Results": check_shodan(domain),
        "LeakCheck Results": check_leakcheck(email),
        "DeHashed Results": check_dehashed(email)
    }
    report_path = generate_pdf(domain, report_data)
    return report_path
