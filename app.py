from flask import Flask, render_template, request
import os
from qr_module.qr_decoder import decode_qr

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/upload', methods=['POST'])
def upload():

    file = request.files['qr_image']

    if file:

        filepath = os.path.join('static/uploads', file.filename)

        file.save(filepath)

        qr_data = decode_qr(filepath)

        return f"Extracted QR Data: {qr_data}"

    return "No file uploaded"

@app.route('/result')
def result():
    return render_template('result.html')

@app.route('/history')
def history():
    return render_template('history.html')

if __name__ == '__main__':
    app.run(debug=True)