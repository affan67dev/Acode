# Clothing E-commerce Platform

This repository was rebuilt from the unrelated legacy Acode codebase into a clothing commerce application.

## Stack
- Node.js 20+
- Express
- SQLite via better-sqlite3
- JWT authentication in HttpOnly cookies
- Razorpay server-side order creation/signature verification
- Vanilla responsive frontend

## Run
1. Copy `.env.example` to `.env`.
2. Set a strong `JWT_SECRET` and admin credentials.
3. Add Razorpay credentials for online payments.
4. Run `npm install`.
5. Run `npm start`.
6. Open `http://localhost:3000`.

The first server start creates the SQLite schema and an admin account from environment variables.

## Payment
The frontend never marks a Razorpay payment successful by itself. The server creates the payment order and verifies Razorpay's signature before creating/confirming a paid order. Production deployment requires real Razorpay credentials and webhook reconciliation.

## Returns
Eligible delivered orders can request a return within the configured 10-day window. The API records the request and keeps the order auditable.

## Production checklist
Use HTTPS, a managed database/object store, rate limiting/WAF, transactional email/SMS, Razorpay webhooks, backups, monitoring, and a secrets manager before high-volume production use.
