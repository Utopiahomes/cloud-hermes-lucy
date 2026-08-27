-- Development bootstrap only. Production roles/passwords are provisioned by the
-- deployment secret manager before migrations run.
CREATE ROLE lucy_app LOGIN PASSWORD 'local-app-only-change-me' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE lucy TO lucy_app;

\connect lucy

CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS lucy AUTHORIZATION lucy_owner;
GRANT USAGE ON SCHEMA lucy TO lucy_app;
ALTER DEFAULT PRIVILEGES FOR ROLE lucy_owner IN SCHEMA lucy
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lucy_app;
ALTER DEFAULT PRIVILEGES FOR ROLE lucy_owner IN SCHEMA lucy
  GRANT USAGE, SELECT ON SEQUENCES TO lucy_app;

