-- Never run against a real database. compose.test.yaml owns this tmpfs cluster.
CREATE ROLE lucy_app LOGIN PASSWORD 'synthetic-app-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE lucy_public_runtime LOGIN PASSWORD 'synthetic-public-runtime-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_public LOGIN PASSWORD 'synthetic-utopia-public-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_raymond_routine LOGIN PASSWORD 'synthetic-raymond-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_routine LOGIN PASSWORD 'synthetic-utopia-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_alpha_routine LOGIN PASSWORD 'synthetic-alpha-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_directory_admission LOGIN PASSWORD 'synthetic-directory-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_cost_admission LOGIN PASSWORD 'synthetic-cost-admission-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_cost_recovery_writer LOGIN PASSWORD 'synthetic-cost-recovery-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_authority_transition LOGIN PASSWORD 'synthetic-authority-transition-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_authority_recovery_writer LOGIN PASSWORD 'synthetic-authority-recovery-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_policy LOGIN PASSWORD 'synthetic-utopia-policy-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_sensitive_workflow LOGIN PASSWORD 'synthetic-utopia-workflow-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_raymond_policy LOGIN PASSWORD 'synthetic-raymond-policy-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_raymond_sensitive_workflow LOGIN PASSWORD 'synthetic-raymond-workflow-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_finality LOGIN PASSWORD 'synthetic-utopia-finality-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_authority_writer LOGIN PASSWORD 'synthetic-utopia-authority-writer-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_cost_writer LOGIN PASSWORD 'synthetic-utopia-cost-writer-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_authority_recovery LOGIN PASSWORD 'synthetic-utopia-authority-recovery-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_utopia_cost_recovery LOGIN PASSWORD 'synthetic-utopia-cost-recovery-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_migration NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_security_function_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_directory_function_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_cost_function_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE lucy_authority_function_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT lucy_security_function_owner TO lucy_owner;
GRANT lucy_directory_function_owner TO lucy_owner;
GRANT lucy_cost_function_owner TO lucy_owner;
GRANT lucy_authority_function_owner TO lucy_owner;
GRANT lucy_migration TO lucy_owner;
GRANT CONNECT ON DATABASE lucy_test TO lucy_app;
GRANT CONNECT ON DATABASE lucy_test TO lucy_public_runtime;
GRANT CONNECT ON DATABASE lucy_test TO lucy_utopia_public;
GRANT CONNECT ON DATABASE lucy_test TO lucy_directory_admission;
GRANT CONNECT ON DATABASE lucy_test TO lucy_cost_admission, lucy_cost_recovery_writer;
GRANT CONNECT ON DATABASE lucy_test TO
  lucy_authority_transition, lucy_authority_recovery_writer;
GRANT CONNECT ON DATABASE lucy_test TO
  lucy_raymond_routine, lucy_utopia_routine, lucy_alpha_routine;
GRANT CONNECT ON DATABASE lucy_test TO
  lucy_utopia_policy, lucy_utopia_sensitive_workflow,
  lucy_raymond_policy, lucy_raymond_sensitive_workflow, lucy_utopia_finality;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA lucy AUTHORIZATION lucy_owner;
GRANT USAGE ON SCHEMA lucy TO lucy_app;
GRANT USAGE ON SCHEMA lucy TO lucy_public_runtime;
GRANT USAGE ON SCHEMA lucy TO lucy_utopia_public;
GRANT USAGE ON SCHEMA lucy TO lucy_directory_admission;
GRANT USAGE ON SCHEMA lucy TO lucy_cost_admission, lucy_cost_recovery_writer;
GRANT USAGE ON SCHEMA lucy TO
  lucy_authority_transition, lucy_authority_recovery_writer;
GRANT USAGE ON SCHEMA lucy TO
  lucy_raymond_routine, lucy_utopia_routine, lucy_alpha_routine;
GRANT USAGE ON SCHEMA lucy TO
  lucy_utopia_policy, lucy_utopia_sensitive_workflow,
  lucy_raymond_policy, lucy_raymond_sensitive_workflow, lucy_utopia_finality;
ALTER DEFAULT PRIVILEGES FOR ROLE lucy_owner IN SCHEMA lucy
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lucy_app;
ALTER DEFAULT PRIVILEGES FOR ROLE lucy_owner IN SCHEMA lucy
  GRANT USAGE, SELECT ON SEQUENCES TO lucy_app;
