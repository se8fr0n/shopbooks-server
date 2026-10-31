# ShopBooks server

Real database, user accounts with roles, locked records, tamper-evident audit log, and an
offline-safe sync API. The offline frontend is the next step and goes in `public/`.

## What is enforced where

| Rule | Enforced by |
|---|---|
| Saved sales, payments, expenses, stock moves and audit entries cannot be edited or deleted | PostgreSQL triggers in `schema.sql` (not the app) |
| A sale can only be voided, with a reason; stock goes back automatically | Trigger + `sale.void` |
| Cashier cannot see buy prices, expenses, reports, or void | Server roles |
| Disabled staff lose access immediately, even with a saved login | Server checks the account on every request |
| Audit log tampering is detectable | Hash chain, check with `GET /api/audit/verify` |
| Retrying after a dropped connection never creates duplicate sales | Every operation has a unique id (`applied_ops`) |

Roles: owner (everything, manages staff, audit) / manager (stock, expenses, reports, void) / cashier (sales and debt payments).

## Setup (about 15 minutes)

1. Make a PostgreSQL database. Free options: Neon, Supabase, or Render. Copy its connection string.
2. `cp .env.example .env` and fill in `DATABASE_URL` and `JWT_SECRET`.
   Set `PGSSL=1` if your host needs SSL.
3. `npm install`
4. `npm run schema` (needs `psql`), or paste `schema.sql` into the host's SQL editor.
5. `npm start`
6. Create the owner account once: POST `/api/setup` with name, username and a password of 8+ characters
   (the frontend will have a screen for this).

## Hosting

Deploy this folder to Render, Railway or Fly.io as a Node web service. Start command: `npm start`.
Add `DATABASE_URL`, `JWT_SECRET` and `PGSSL` as environment variables. Then connect your custom domain there.

## Backups

- Turn on the database host's automatic daily backups.
- `backup.sh` makes a compressed dump and keeps 30 days. Run it from cron and copy the folder to Google Drive.
- For the locks to be truly strong, the app should connect with a database user that is not the database owner,
  so nobody can drop the triggers through the app.

## Offline design (used by the frontend)

1. The phone/laptop keeps a full copy of the data in IndexedDB (from `GET /api/snapshot`).
2. Every sale, payment, expense or stock change is written locally first and added to an outbox, each with a unique id.
3. When online, the outbox is sent to `POST /api/sync/push` in order. Already-applied ids are safely ignored.
4. If two devices sell the last item while offline, stock may go below zero. The server accepts the sale
   (the goods already left) and returns a warning for the manager to see.
5. Sale numbers are given by the server, so an offline receipt shows a temporary number until it syncs.
