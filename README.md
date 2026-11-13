# kortes.org

Static site + Cloudflare Worker.

- `public/` – the website (served as Workers static assets)
- `src/worker.js` – client-area login, contact form (`/api/contact`), Substack feed (`/api/posts`)
- `migrations/` – D1 schema (database `kortes`)
- `scripts/new-user.mjs` – generates a client username/password and the SQL to add it

Protected client reports are stored in the `PRIVATE` KV namespace (key = URL slug), never in this public repo.
Secrets (set in Cloudflare, not here): `SESSION_SECRET`, optional `HUBSPOT_TOKEN`.
