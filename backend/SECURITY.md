# Admin import configuration

`POST /api/domains/import` requires the `X-Admin-Secret` request header. The
backend reads `TYPOGUARD_ADMIN_SECRET` from its environment for each request;
if it is unset or empty, the import endpoint rejects every request. Scanning
and read-only domain lookups remain public.

Generate a long, random secret for production (for example,
`python -c "import secrets; print(secrets.token_urlsafe(32))"`) and configure it
in the backend hosting platform's environment-variable settings. Do not put this
credential in a `VITE_` variable, frontend code, browser storage, logs, or a
committed `.env` file. The `backend/.env.example` file contains placeholders
only.

Set `TYPOGUARD_CORS_ORIGINS` to a comma-separated allowlist of exact trusted
frontend origins, including scheme and host. CORS is not authentication; keep
the admin secret private even when browser origins are restricted.

## Scan rate limit

The public scan API allows 30 requests per client address per 60-second fixed
window. The in-memory counter is bounded and returns HTTP 429 with a
`Retry-After` header. Its state is local to one process and resets on restart;
it is suitable only for the current single-instance SQLite deployment shape.
The limit uses the ASGI connection client address. Behind a reverse proxy,
configure trusted forwarded-address handling at the ASGI server or enforce a
limit at the proxy. Do not trust arbitrary client-supplied forwarding headers.
If the service later runs multiple instances or workers, move the limiter to a
shared store such as Redis.
