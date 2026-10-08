# CyberShield — DDoS Protection System

SY B.Tech Computer Engineering project prototype.

## Current stage

This first build provides the project foundation:

- Professional CyberShield SOC-style UI
- Flask backend
- SQLite traffic/event logging
- Dashboard
- Live Traffic page
- Alerts page
- Traffic Logs page
- Settings page
- Threshold-based normal/suspicious classification
- Safe local synthetic-event demonstration buttons

## Run

### 1. Create/activate a virtual environment (recommended)

Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Start

```powershell
python app.py
```

### 4. Open

http://127.0.0.1:5000

## Important

The "Simulate Suspicious Event" button creates a synthetic observation in the local SQLite database. It does not generate traffic toward external systems.

## Planned next stages

1. Improve detection engine
2. Add configurable threshold persistence
3. Add request metadata
4. Add stronger rate-limiting behavior
5. Add dashboard analytics
6. Add controlled local testing
7. Prepare testing evidence, report and presentation
