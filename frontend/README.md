# TypoGuard frontend

React and Vite dashboard for the local TypoGuard API.

## Run locally

1. Start the backend from `backend`:

   ```powershell
   .\venv\Scripts\python.exe -m uvicorn app.main:app --reload
   ```

2. In `frontend`, copy `.env.example` to `.env` if you need to override the API URL, then install and start:

   ```powershell
   npm install
   npm run dev
   ```

The default API base URL is `http://127.0.0.1:8000`. Scans are sent as JSON to
`POST /api/scan/`; the frontend never requests the URL entered by the user.
Configure `VITE_API_BASE_URL` at frontend build time if the API is hosted
elsewhere. For a different browser origin, add that exact origin to the
backend's comma-separated `TYPOGUARD_CORS_ORIGINS` environment variable.

Scan reports display the backend's risk signals and hostname fingerprint. Scan
history is stored only in this browser (not on the server), with URL credentials,
query parameters, and fragments omitted from saved entries. Clear history from
the Scan history section to remove those local records.

Run the production build and frontend tests with `npm run build` and
`npm test`.
