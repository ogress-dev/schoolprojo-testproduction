# URL Scanner Backend

FastAPI backend for URL scanning and classification.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## API Endpoints

- `POST /api/scan` - Scan a URL and get classification results
- `POST /api/scan/save` - Scan a URL and save results to database
- `GET /api/scans` - Get all saved scans
- `GET /api/scans/{scan_id}` - Get detailed scan by ID
- `GET /api/statistics` - Get classification statistics
- `DELETE /api/scans/{scan_id}` - Delete a scan

## Database

The application uses SQLite by default. The database file `url_scanner.db` will be created automatically.

## CORS

CORS is configured to allow all origins for development. In production, update the `allow_origins` in `main.py`.# schoolprojo-testproduction
