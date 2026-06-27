# REASONIX.md — LeaseSign

## Stack

- **Runtime:** Node.js >= 18.0.0
- **Backend:** Express 4.x, single file (`server/index.js`, ~2381 lines)
- **Frontend:** React (via Babel standalone in `public/index.html` — single-file SPA, no build step)
- **Database:** PostgreSQL (via `pg`) with JSON file storage fallback (`data/`)
- **Auth:** JWT (`jsonwebtoken`) + bcryptjs password hashing (10 rounds)
- **PDF:** PDFKit for TAR TXR-2001 lease form generation
- **Email:** Nodemailer (SMTP — Gmail, SendGrid, SES)

## Layout

- `server/index.js` — All backend logic: routes, auth middleware, DB, email, PDF generation
- `public/index.html` — Entire frontend (React inline via Babel standalone)
- `data/` — JSON file storage (gitignored — created at runtime)
- `generated/` — Output PDFs (gitignored)
- `uploads/` — User uploads (gitignored)

## Commands

| Command | Action |
|---------|--------|
| `npm start` / `npm run dev` | Start server (both run `node server/index.js`) |

No test runner, linter, formatter, or type checker is configured.

## Conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, etc.) per `CONTRIBUTING.md`
- **JS style:** ES6+, `const`/`let` (no `var`), async/await
- **API routes:** RESTful, protected routes use `auth` middleware
- **Error responses:** Consistent shape `{ error: "message" }`
- **Audit logging:** Every document change is logged server-side

## Watch out for

- **Single-file backend:** `server/index.js` is 2381 lines — search before duplicating logic
- **No test suite:** No test framework installed; manual verification via `curl http://localhost:3000/api/health`
- **In-memory rate limiter:** Login rate limiting resets on server restart
- **JSON storage by default:** Set `DATABASE_URL` in `.env` to switch to PostgreSQL
- **JWT secret:** Must be set in `.env` for persistent sessions across restarts
- **Setup:** Copy `.env.example` → `.env`, then `npm start`
