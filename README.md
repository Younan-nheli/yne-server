# YNE Server v1
Central backend for YNE Master, YNE POS, restaurants and licenses.

Requirements: Node.js 20+, PostgreSQL 16+ (or Docker Desktop).

1. `npm install`
2. `docker compose up -d`
3. Run `schema.sql` against database `yne_server`
4. Copy `.env.example` to `.env`
5. Generate a master password hash:
`node -e "console.log(require('bcryptjs').hashSync('YOUR_PASSWORD',12))"`
6. Set `MASTER_USERNAME`, `MASTER_PASSWORD_HASH`, `JWT_SECRET`, `DATABASE_URL`
7. `npm start`

API:
POST /api/master/login
POST /api/master/restaurants
GET /api/master/restaurants
PATCH /api/master/restaurants/:id/status
PATCH /api/master/licenses/:id
POST /api/pos/login
POST /api/pos/license/verify
GET /api/health

Do not deploy publicly without HTTPS, firewall rules, backups and production secrets.
