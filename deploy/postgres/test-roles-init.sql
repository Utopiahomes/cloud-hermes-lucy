-- Only the separate disposable role-test cluster uses this bootstrap account.
CREATE ROLE lucy_migrator LOGIN PASSWORD 'synthetic-migrator-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE EXTENSION IF NOT EXISTS vector;
ALTER DATABASE lucy_roles_test OWNER TO lucy_migrator;
