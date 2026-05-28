# SafeNet QR Shield

QR phishing detection platform built with Flask. Scan QR codes from an image or webcam and get a clear threat report with risk score, SSL checks, and scan history.

## Features

- Upload or drag-and-drop QR image scanning
- Live webcam capture UI
- Threat report page (risk score, indicators, recommendations)
- Scan history with search and filters
- Dashboard and admin analytics views
- Dark / light theme with persistent preference
- Responsive layout for mobile, tablet, and desktop

## Tech stack

- Python · Flask · Jinja2
- Bootstrap 5 · Chart.js · Lucide icons
- OpenCV / pyzbar (QR decode module — team integration)
- scikit-learn (ML — team integration)

## Quick start

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**

## Project structure

```
├── app.py                 # Application entry
├── config.py              # Settings
├── routes/                # Page + API blueprints
├── services/mock_data.py  # Demo data (replace with DB/ML)
├── static/                # CSS, JS, uploads
├── templates/             # HTML pages
├── qr_module/             # QR decoding
└── SETUP.md               # Integration guide
```

## Integration

See **[SETUP.md](SETUP.md)** for how to connect QR decoding, analysis modules, and the database.
