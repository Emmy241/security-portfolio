-- 01-roles.sql — runs as superuser on first init

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The app role. It will later be made OWNER of every table (V-30).
CREATE ROLE lendstack_app LOGIN PASSWORD 'LendStack_App_Pr0d_2024!';
CREATE ROLE lendstack_ro  LOGIN PASSWORD 'LendStack_ReadOnly_2024!';

GRANT CONNECT ON DATABASE lendstack TO lendstack_app, lendstack_ro;
GRANT USAGE   ON SCHEMA public    TO lendstack_app, lendstack_ro;
