from flask import Flask, render_template, request, send_file
from main import run_recon
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        email = request.form['email']

        if not domain or not email:
            return render_template('index.html', error="Both fields are required.")

        output_path = run_recon(domain, email)

        if output_path and os.path.exists(output_path):
            return send_file(output_path, as_attachment=True)
        else:
            return render_template('index.html', error="Failed to generate report.")

    return render_template('index.html')
