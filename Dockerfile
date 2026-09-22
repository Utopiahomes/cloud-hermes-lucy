FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN groupadd --system --gid 10001 lucy \
    && useradd --system --uid 10001 --gid lucy --home-dir /nonexistent lucy

WORKDIR /app
COPY pyproject.toml ./
COPY deploy/render/requirements.lock ./deploy/render/requirements.lock
COPY deploy/postgres/bootstrap_cloud_v1_2.py ./deploy/postgres/bootstrap_cloud_v1_2.py
COPY deploy/postgres/bootstrap_realm_cloud_v1_3.py ./deploy/postgres/bootstrap_realm_cloud_v1_3.py
COPY deploy/postgres/migrate_realm_cloud_v1_3.py ./deploy/postgres/migrate_realm_cloud_v1_3.py
COPY deploy/postgres/verify_private_memory_head_v1_3.py ./deploy/postgres/verify_private_memory_head_v1_3.py
COPY deploy/postgres/recover_empty_raymond_realm_v1_3.py ./deploy/postgres/recover_empty_raymond_realm_v1_3.py
COPY deploy/postgres/commission_telegram_stage1_v1.py ./deploy/postgres/commission_telegram_stage1_v1.py
COPY deploy/postgres/commission_realm_runtime_v1_3.py ./deploy/postgres/commission_realm_runtime_v1_3.py
COPY deploy/postgres/commission_public_projection_v1.py ./deploy/postgres/commission_public_projection_v1.py
COPY deploy/postgres/release_public_knowledge_v1.py ./deploy/postgres/release_public_knowledge_v1.py
COPY deploy/postgres/migrate_telegram_stage2_v1.py ./deploy/postgres/migrate_telegram_stage2_v1.py
COPY deploy/postgres/activate_telegram_stage2_v1.py ./deploy/postgres/activate_telegram_stage2_v1.py
COPY deploy/postgres/rebind_executors_cloud_v1_2.py ./deploy/postgres/rebind_executors_cloud_v1_2.py
COPY deploy/postgres/inspect_unresolved_cloud_v1_2.py ./deploy/postgres/inspect_unresolved_cloud_v1_2.py
COPY deploy/postgres/recover_expired_synthetic_retrieval_cloud_v1_2.py ./deploy/postgres/recover_expired_synthetic_retrieval_cloud_v1_2.py
COPY deploy/postgres/replay_authorized_deletion_cloud_v1_2.py ./deploy/postgres/replay_authorized_deletion_cloud_v1_2.py
COPY deploy/postgres/replay_authorized_deletion_cloud_v1_3.py ./deploy/postgres/replay_authorized_deletion_cloud_v1_3.py
COPY deploy/postgres/provision_realm_foundation_v1_3.py ./deploy/postgres/provision_realm_foundation_v1_3.py
COPY deploy/postgres/provision_realm_bindings_v1_3.py ./deploy/postgres/provision_realm_bindings_v1_3.py
COPY deploy/postgres/provision_workspaces_authority_v1.py ./deploy/postgres/provision_workspaces_authority_v1.py
COPY deploy/postgres/provision_synthetic_authority_v1_3.py ./deploy/postgres/provision_synthetic_authority_v1_3.py
COPY deploy/postgres/render_security_v1_2_sql.py ./deploy/postgres/render_security_v1_2_sql.py
COPY deploy/postgres/render_security_v1_3_sql.py ./deploy/postgres/render_security_v1_3_sql.py
COPY deploy/postgres/render_recovery_roles_v1_3.py ./deploy/postgres/render_recovery_roles_v1_3.py
COPY deploy/postgres/production_bootstrap.sql.example ./deploy/postgres/production_bootstrap.sql.example
COPY deploy/postgres/production_roles_v1.2.sql.example ./deploy/postgres/production_roles_v1.2.sql.example
COPY deploy/postgres/production_realm_roles_v1.3.sql.example ./deploy/postgres/production_realm_roles_v1.3.sql.example
COPY deploy/postgres/production_recovery_roles_v1.3.sql.example ./deploy/postgres/production_recovery_roles_v1.3.sql.example
COPY deploy/postgres/configure_security_v1.2.sql.example ./deploy/postgres/configure_security_v1.2.sql.example
COPY deploy/render/utopia-public-projection.v0.json ./deploy/render/utopia-public-projection.v0.json
COPY alembic.ini hermes.lock ./
COPY migrations ./migrations
COPY src ./src
RUN pip install --no-cache-dir --require-hashes -r deploy/render/requirements.lock

USER 10001:10001
CMD ["python", "-m", "lucy.runtime"]
