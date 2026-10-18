-- 02-schema.sql — tables created by superuser, then reassigned to lendstack_app.
-- Reassignment is the setup for V-30: owner bypasses RLS unless FORCE is set.

CREATE TABLE tenants (
  id          uuid PRIMARY KEY,
  slug        text UNIQUE NOT NULL,
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenants(id),
  email          text UNIQUE NOT NULL,
  password_hash  text NOT NULL,
  role           text NOT NULL CHECK (role IN ('owner','analyst','auditor','service')),
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id          uuid PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  text NOT NULL,
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenants(id),
  name           text NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('operating','reserve')),
  balance_cents  bigint NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE invoices (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  account_id   uuid NOT NULL REFERENCES accounts(id),
  number       text NOT NULL,
  amount_cents bigint NOT NULL,
  currency     text NOT NULL DEFAULT 'USD',
  status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open','paid','overdue')),
  due_date     date,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE loan_applications (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  applicant_name  text NOT NULL,
  zip             text NOT NULL,
  income_cents    bigint NOT NULL,
  requested_cents bigint NOT NULL,
  decision        text NOT NULL DEFAULT 'pending' CHECK (decision IN ('approved','denied','pending')),
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE transfers (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id),
  from_account_id  uuid NOT NULL REFERENCES accounts(id),
  to_account_id    uuid NOT NULL REFERENCES accounts(id),
  amount_cents     bigint NOT NULL,
  idempotency_key  text,                       -- V-19: nullable, unused
  status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','approved','rejected','settled')),
  created_by       uuid NOT NULL REFERENCES users(id),
  approved_by      uuid REFERENCES users(id),  -- V-33: no check that approver != creator
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ledger_entries (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  transfer_id  uuid REFERENCES transfers(id),
  account_id   uuid NOT NULL REFERENCES accounts(id),
  direction    text NOT NULL CHECK (direction IN ('debit','credit')),
  amount_cents bigint NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE webhooks (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  url         text NOT NULL,
  secret      text NOT NULL,
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- V-31: no tenant_id column. Scoping is only possible via a join to invoices.
CREATE TABLE files (
  id            uuid PRIMARY KEY,
  invoice_id    uuid NOT NULL REFERENCES invoices(id),
  filename      text NOT NULL,
  content_type  text NOT NULL,
  storage_path  text NOT NULL,
  uploaded_by   uuid NOT NULL REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  actor_id     uuid REFERENCES users(id),
  action       text NOT NULL,
  target_type  text,
  target_id    uuid,
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE support_messages (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  user_id     uuid NOT NULL REFERENCES users(id),
  role        text NOT NULL CHECK (role IN ('user','assistant')),
  content     text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX ON users (tenant_id);
CREATE INDEX ON refresh_tokens (user_id);
CREATE INDEX ON invoices (tenant_id, status);
CREATE INDEX ON invoices (tenant_id, due_date);
CREATE INDEX ON loan_applications (tenant_id);
CREATE INDEX ON transfers (tenant_id, created_at);
CREATE INDEX ON files (invoice_id);
CREATE INDEX ON audit_log (tenant_id, created_at);
CREATE INDEX ON support_messages (tenant_id, created_at);

-- V-30 setup: the app role becomes OWNER of every table.
ALTER TABLE tenants           OWNER TO lendstack_app;
ALTER TABLE users             OWNER TO lendstack_app;
ALTER TABLE refresh_tokens    OWNER TO lendstack_app;
ALTER TABLE accounts          OWNER TO lendstack_app;
ALTER TABLE invoices          OWNER TO lendstack_app;
ALTER TABLE loan_applications OWNER TO lendstack_app;
ALTER TABLE transfers         OWNER TO lendstack_app;
ALTER TABLE ledger_entries    OWNER TO lendstack_app;
ALTER TABLE webhooks          OWNER TO lendstack_app;
ALTER TABLE files             OWNER TO lendstack_app;
ALTER TABLE audit_log         OWNER TO lendstack_app;
ALTER TABLE support_messages  OWNER TO lendstack_app;

-- Read-only role for reporting / the CI check
GRANT SELECT ON ALL TABLES IN SCHEMA public TO lendstack_ro;
