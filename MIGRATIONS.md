# Database migrations

Apply every forward migration in filename order before starting the controller. Back up the database first. Migration `000003` stops if existing Google account links conflict; resolve those rows before retrying.

With `psql` installed and a PostgreSQL database selected by `DATABASE_URL`:

```sh
set -eu
for migration in internal/db/sqlc/migrations/*.up.sql; do
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction -f "$migration"
done
```

The controller checks for required tables and indexes at startup. It does not apply migrations automatically.
