# SafeNet QR Shield — Setup & Integration Guide

Frontend and Flask integration (ML, QR decoding, and cyber analysis modules are wired in separately).

## Quick Start

```bash
# From project root
cd QR-Phishing-Detector-main

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt

# Run the application
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

## Project Structure

```
QR-Phishing-Detector-main/
├── app.py                      # Flask app factory + blueprint registration
├── config.py                   # Configuration (uploads, secrets, demo mode)
├── routes/
│   ├── main.py                 # Page routes (HTML)
│   └── api.py                  # JSON API for AJAX (/api/*)
├── services/
│   └── mock_data.py            # Demo data until backend modules integrate
├── static/
│   ├── css/
│   │   ├── variables.css       # Design tokens (dark/light)
│   │   ├── main.css            # Global layout, navbar, footer
│   │   ├── theme.css           # Theme toggle styles
│   │   ├── components.css      # Cards, buttons, tables, forms
│   │   ├── animations.css      # Motion, spinners, skeletons
│   │   └── pages/              # Page-specific styles
│   ├── js/
│   │   ├── theme.js            # localStorage theme persistence
│   │   ├── particles.js        # Animated particle background
│   │   ├── charts.js           # Chart.js helpers
│   │   ├── main.js             # Global UI (navbar, counters, flash)
│   │   ├── scan.js             # AJAX upload + scan animation
│   │   ├── webcam.js           # Webcam HUD UI
│   │   ├── result.js           # Result page charts
│   │   ├── history.js          # History charts
│   │   ├── dashboard.js        # Dashboard charts
│   │   └── admin.js            # Admin charts
│   └── uploads/                # Uploaded QR images
└── templates/
    ├── layout.html             # Master layout
    ├── components/             # Navbar, footer, flash, theme toggle
    └── *.html                  # All pages
```

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Homepage with live stats |
| `/scan` | GET | QR upload scan UI |
| `/upload` | POST | Image upload (AJAX or form) |
| `/webcam` | GET | Live webcam scanner |
| `/result/<scan_id>` | GET | Threat analysis report |
| `/history` | GET | Searchable scan history |
| `/dashboard` | GET | SOC analytics dashboard |
| `/admin` | GET | Enterprise admin panel |
| `/login` | GET/POST | Authentication (session demo) |
| `/register` | GET/POST | Registration (session demo) |
| `/logout` | GET | Clear session |
| `/api/stats/live` | GET | Live stats JSON |
| `/api/dashboard` | GET | Dashboard data JSON |
| `/api/history` | GET | Paginated history JSON |
| `/api/scan/<id>` | GET | Scan result JSON |
| `/api/webcam/complete` | POST | Webcam scan completion |

## Integration Points for Other Team Members

### Member 2 — QR Decoding (`qr_module/qr_decoder.py`)

In `routes/main.py` → `upload()`:

```python
from qr_module.qr_decoder import decode_qr

# After saving file:
decoded_url = decode_qr(upload_path)
result = get_real_scan_result(decoded_url)  # Replace mock
```

### Member 3 — Cybersecurity Analysis

Replace `services/mock_data.py` calls with real analysis:

```python
# Example structure expected by result.html:
{
    "scan_id": "...",
    "decoded_url": "...",
    "phishing_probability": 85.2,
    "risk_score": 92,
    "verdict": "malicious",  # safe | suspicious | malicious
    "ssl_status": "invalid",
    "blacklist_status": "listed",
    "suspicious_indicators": [...],
    "recommendations": [...],
}
```

### Member 4 — MySQL Database

1. Store scans in MySQL instead of `session` and `mock_data.py`.
2. Update `get_scan_history()`, `get_dashboard_stats()`, `get_admin_stats()` to query DB.
3. Wire login/register to real user table with password hashing (e.g. `werkzeug.security`).

### Environment Variables

```bash
set SECRET_KEY=your-production-secret
set DEMO_MODE=false
```

## Theme System

- Default: **dark mode** (zinc neutrals, single blue accent)
- Toggle in navbar; persisted in `localStorage` key `safenet-theme`
- Design: Inter typography, Lucide icons, minimal motion — no particle/grid effects
- Tokens in `static/css/variables.css`

## Tech Stack (CDN)

- Bootstrap 5.3.3 (grid only)
- Lucide icons
- Chart.js 4.4.1
- Google Fonts: Inter, IBM Plex Mono

## Demo Mode

`config.DEMO_MODE=true` (default) uses `services/mock_data.py` for all scan results, history, and analytics. Set `DEMO_MODE=false` when backend modules are ready.

## Production Checklist

- [ ] Set strong `SECRET_KEY`
- [ ] Disable Flask `debug=True`
- [ ] Use Gunicorn/uWSGI behind nginx
- [ ] Connect MySQL and remove mock data
- [ ] Implement real auth (Flask-Login + hashed passwords)
- [ ] Validate/sanitize all uploads
- [ ] Enable HTTPS and `SESSION_COOKIE_SECURE=True`

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Styles not loading | Ensure `static/` folder exists; hard-refresh browser |
| Upload fails | Check `static/uploads/` is writable |
| Camera not working | Use HTTPS or localhost; allow browser permissions |
| Charts blank | Verify Chart.js CDN loads; check browser console |

---

**SafeNet QR Shield** — Built for portfolio demos, hackathons, and enterprise SOC workflows.
