# ipVision 2.0 — Network Signal & Security Scanner

ipVision is a high-performance, security-hardened web application that provides real-time IP address geolocation, autonomous system (BGP) carrier routing analysis, and VPN/proxy threat detection.

## Key Features

- **Validated Lookup**: Real-time IPv4/IPv6 validation locally in Python and in the browser before any network queries.
- **Threat Detection**: Instant proxy, VPN, Tor exit node, and cloud/datacenter detection.
- **Clean View**: Privacy toggle that conceals postal codes and organization flags to avoid shoulder-surfing leaks.
- **Single Active Session**: Secure account model where logging in on a new device or browser automatically supersedes older sessions.
- **Supabase Integration**: Cloud persistence with PostgreSQL Row Level Security (RLS) guaranteeing users can only read and manage their own scans.
- **Zero Inline Scripts & Strict CSP**: Hardened Content Security Policy, HttpOnly SameSite=Lax cookies, and anti-CSRF protections.
- **Modernized Feedback (Step 11)**: Delightful interactive feedback system with sentiment ratings and category tagging.
- **Radar Noir Design**: A sleek, dark cyber-instrument interface with GPU-accelerated neon letter startup and sweeping tube light animations.

## Running Locally

```bash
python server.py
```

Then open your browser to [http://localhost:3000](http://localhost:3000).

## Running Tests

```bash
python -m unittest tests/test_backend.py
```

## Environment Variables

Copy `.env.example` to `.env` or set these in Vercel:

- `PORT` — Defaults to `3000`.
- `ENVIRONMENT` — `development` or `production`.
- `SUPABASE_URL` — Your Supabase project URL (`https://xyz.supabase.co`).
- `SUPABASE_ANON_KEY` — Supabase Anonymous Client Key.
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase Service Role Key (kept strictly on server).
- `SESSION_SECRET` — 32+ character random string for HMAC token signing.
- `RESEND_API_KEY` — (Optional) Resend API key for forwarding visitor feedback.
- `FEEDBACK_FROM_EMAIL` — (Optional) Verified sender email address in Resend.
