from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError

from deploy.postgres.release_public_knowledge_v1 import (
    PublicKnowledgeReleaseConfig,
    PublicKnowledgeReleaseError,
    PublicKnowledgeReleaseManifestV1,
    _activate,
    _approve,
    _stage,
)
from deploy.postgres.render_security_v1_3_sql import render_realm_roles
from lucy.db import create_session_factory
from lucy.db.models import (
    PublicProjectionCandidateRow,
    SecurityRealmRow,
    TenantAccountRow,
    WalletRegistrationRow,
)
from lucy.publication import (
    PublicationRejected,
    PublicProjectionPublisher,
    PublicProjectionReader,
    knowledge_snapshot,
    snapshot_digest,
)
from lucy.readiness import ReadinessError, admitted_session_factory
from lucy.tenancy import ScopeNotFound, TenancyService

DATABASE_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_DATABASE_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
PUBLIC_DATABASE_URL = os.getenv("LUCY_TEST_PUBLIC_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="requires PostgreSQL integration database")
SYNTHETIC_PORTS = {54329, 54339}


@pytest.fixture(autouse=True)
def clean_r1_tables() -> None:
    assert OWNER_DATABASE_URL is not None
    parsed = make_url(OWNER_DATABASE_URL)
    if (parsed.database, parsed.host) != ("lucy_test", "127.0.0.1") or (
        parsed.port not in SYNTHETIC_PORTS
    ):
        raise RuntimeError("refusing to clear a non-synthetic database")
    engine = create_engine(OWNER_DATABASE_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.public_projection_events, lucy.public_projection_routes, "
                "lucy.public_projection_versions, lucy.public_projection_approvals, "
                "lucy.public_projection_candidates, lucy.lucy_instances, "
                "lucy.node_memberships, lucy.channel_bindings, lucy.wallet_registrations, "
                "lucy.workspaces, lucy.realm_bindings, lucy.node_tenures, lucy.security_realms, "
                "lucy.nodes, lucy.tenant_accounts, lucy.principals CASCADE"
            )
        )
    engine.dispose()


def _foundation(service: TenancyService, slug: str, host: str):
    return service.create_node_foundation(
        account_slug=slug,
        account_name=slug.title(),
        node_slug=slug,
        node_name=slug.title(),
        node_kind="organization",
        realm_slug=f"{slug}-realm",
        workspace_slug="website",
        hostname=host,
    )


def test_synthetic_utopia_public_slice_is_scoped_immutable_and_withdrawable() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    tenancy = TenancyService(sessions)
    publisher = PublicProjectionPublisher(sessions)
    assert PUBLIC_DATABASE_URL is not None
    public_sessions = create_session_factory(PUBLIC_DATABASE_URL)
    reader = PublicProjectionReader(public_sessions)
    actor = tenancy.create_principal(
        issuer="https://synthetic-idp.invalid", subject="ray", kind="human", display_name="Ray"
    )
    utopia = _foundation(tenancy, "utopia", "utopiahomes.test")
    alpha = _foundation(tenancy, "alpha", "alpha.test")
    tenancy.grant_workspace_membership(
        principal_id=actor, workspace_id=utopia.workspace_id, role="owner"
    )
    tenancy.grant_workspace_membership(
        principal_id=actor, workspace_id=alpha.workspace_id, role="owner"
    )
    outsider = tenancy.create_principal(
        issuer="https://synthetic-idp.invalid",
        subject="outsider",
        kind="human",
        display_name="Outsider",
    )
    with pytest.raises(PublicationRejected, match="not authorized"):
        publisher.stage(
            channel_binding_id=utopia.channel_binding_id,
            actor_id=outsider,
            entries=[{"question": "Forged?", "answer": "No", "source": "synthetic://forged"}],
        )

    utopia_candidate, digest = publisher.stage(
        channel_binding_id=utopia.channel_binding_id,
        actor_id=actor,
        entries=[
            {
                "question": "Where is Utopia Homes located?",
                "answer": "Bethany Beach, Delaware.",
                "source": "synthetic://utopia/location",
            }
        ],
    )
    with pytest.raises(PublicationRejected, match="digest"):
        publisher.approve(candidate_id=utopia_candidate, expected_digest="0" * 64, actor_id=actor)
    publisher.approve(candidate_id=utopia_candidate, expected_digest=digest, actor_id=actor)
    publisher.publish(candidate_id=utopia_candidate, actor_id=actor)

    alpha_candidate, alpha_digest = publisher.stage(
        channel_binding_id=alpha.channel_binding_id,
        actor_id=actor,
        entries=[
            {
                "question": "What is Alpha's private canary?",
                "answer": "ALPHA-PRIVATE-CANARY",
                "source": "synthetic://alpha/canary",
            }
        ],
    )
    publisher.approve(candidate_id=alpha_candidate, expected_digest=alpha_digest, actor_id=actor)
    alpha_version = publisher.publish(candidate_id=alpha_candidate, actor_id=actor)

    with (
        pytest.raises(IntegrityError, match="public_projection_routes"),
        sessions.begin() as session,
    ):
        session.execute(
            text(
                "UPDATE lucy.public_projection_routes SET active_version_id=:foreign "
                "WHERE channel_binding_id=:utopia"
            ),
            {"foreign": alpha_version, "utopia": utopia.channel_binding_id},
        )

    answer = reader.answer(
        hostname="UTOPIAHOMES.TEST.", question=" Where is  Utopia Homes located? "
    )
    assert answer.answer == "Bethany Beach, Delaware."
    assert answer.source == "synthetic://utopia/location"
    assert answer.version == 1

    with pytest.raises(ScopeNotFound, match="unavailable"):
        reader.answer(hostname="utopiahomes.test", question="What is Alpha's private canary?")
    with pytest.raises(ScopeNotFound, match="unavailable"):
        reader.answer(hostname="forged-utopia.test", question="Where is Utopia Homes located?")
    with pytest.raises(DBAPIError, match="permission denied"), public_sessions() as public_session:
        public_session.execute(text("SELECT * FROM lucy.public_projection_versions"))

    with (
        pytest.raises(DBAPIError, match="approved public projection bytes are immutable"),
        sessions.begin() as session,
    ):
        session.execute(
            update(PublicProjectionCandidateRow)
            .where(PublicProjectionCandidateRow.id == utopia_candidate)
            .values(snapshot={"schema": "lucy-public-faq-v1", "faqs": []})
        )
    # The database trigger, not just application code, rejects post-review byte changes.
    # SQLAlchemy wraps the trigger exception as DBAPIError.
    # The transaction above is intentionally expected to fail.
    with pytest.raises(PublicationRejected, match="authority transition service"):
        publisher.withdraw(channel_binding_id=utopia.channel_binding_id, actor_id=actor)


def test_realm_public_login_requires_ready_exact_epoch_and_its_own_channel() -> None:
    assert DATABASE_URL and OWNER_DATABASE_URL
    owner_url = make_url(OWNER_DATABASE_URL)
    public_url = owner_url.set(
        username="lucy_utopia_public", password="synthetic-utopia-public-only"
    ).render_as_string(hide_password=False)
    sessions = create_session_factory(DATABASE_URL)
    tenancy = TenancyService(sessions)
    publisher = PublicProjectionPublisher(sessions)
    actor = tenancy.create_principal(
        issuer="https://synthetic-idp.invalid",
        subject="public-gate-owner",
        kind="human",
        display_name="Public Gate Owner",
    )
    utopia = _foundation(tenancy, "utopia", "www.utopiahomes.com")
    tenancy.grant_workspace_membership(
        principal_id=actor, workspace_id=utopia.workspace_id, role="owner"
    )
    now = datetime.now(UTC)
    source = {
        "id": "utopia-source",
        "label": "Utopia Homes",
        "href": "https://www.utopiahomes.com/about",
    }
    candidate, digest = publisher.stage_knowledge(
        channel_binding_id=utopia.channel_binding_id,
        actor_id=actor,
        entries=[
            {
                "id": "utopia-current",
                "service_line": "general",
                "kind": "description",
                "title": "Utopia Homes",
                "approved_text": "Utopia Homes creates distinctive group stays.",
                "topics": ["about"],
                "route": "about",
                "source": source,
                "effective_from": (now - timedelta(days=1)).isoformat(),
                "direct_answer": True,
            },
            {
                "id": "utopia-expired",
                "service_line": "general",
                "kind": "fact",
                "title": "Withdrawn detail",
                "approved_text": "This withdrawn detail must not be returned.",
                "topics": ["about"],
                "route": "about",
                "source": source,
                "effective_from": (now - timedelta(days=2)).isoformat(),
                "effective_until": (now - timedelta(days=1)).isoformat(),
            },
            {
                "id": "utopia-future",
                "service_line": "general",
                "kind": "fact",
                "title": "Future detail",
                "approved_text": "This future detail must not be returned yet.",
                "topics": ["about"],
                "route": "about",
                "source": source,
                "effective_from": (now + timedelta(days=1)).isoformat(),
            },
        ],
    )
    publisher.approve(candidate_id=candidate, expected_digest=digest, actor_id=actor)
    publisher.publish(candidate_id=candidate, actor_id=actor)

    epoch = uuid4()
    owner = create_engine(OWNER_DATABASE_URL)
    with owner.begin() as connection:
        connection.execute(
            text(
                render_realm_roles(
                    realm_slug="utopia",
                    routine_login="lucy_utopia_routine",
                    policy_login="lucy_utopia_policy",
                    workflow_login="lucy_utopia_sensitive_workflow",
                    finality_login="lucy_utopia_finality",
                    public_login="lucy_utopia_public",
                )
            )
        )
        connection.execute(text("UPDATE lucy.lifecycle SET state='ready'"))
        connection.execute(
            text("UPDATE lucy.runtime_admission SET state='quarantined',storage_epoch=:epoch"),
            {"epoch": epoch},
        )

    quarantined = PublicProjectionReader(
        admitted_session_factory(public_url, epoch, journal_required=False)
    )
    with pytest.raises(ReadinessError, match="quarantined"):
        quarantined.knowledge_admitted(
            hostname="www.utopiahomes.com",
            storage_epoch=epoch,
        )

    with owner.begin() as connection:
        connection.execute(text("UPDATE lucy.runtime_admission SET state='ready'"))
    wrong_epoch = uuid4()
    wrong = PublicProjectionReader(
        admitted_session_factory(public_url, wrong_epoch, journal_required=False)
    )
    with pytest.raises(ReadinessError, match="epoch"):
        wrong.knowledge_admitted(
            hostname="www.utopiahomes.com",
            storage_epoch=wrong_epoch,
        )

    projection = quarantined.knowledge_admitted(
        hostname="www.utopiahomes.com",
        storage_epoch=epoch,
    )
    assert [entry.id for entry in projection.entries] == ["utopia-current"]
    assert projection.snapshot_digest == digest
    with pytest.raises(ScopeNotFound, match="unavailable"):
        quarantined.knowledge_admitted(
            hostname="foreign.test",
            storage_epoch=epoch,
        )
    public_engine = create_engine(public_url)
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        public_engine.connect() as connection,
    ):
        connection.execute(text("SELECT * FROM lucy.public_projection_versions"))
    public_engine.dispose()
    owner.dispose()


def test_public_knowledge_release_is_three_step_exact_and_replay_safe() -> None:
    assert DATABASE_URL and OWNER_DATABASE_URL
    sessions = create_session_factory(DATABASE_URL)
    tenancy = TenancyService(sessions)
    publisher = PublicProjectionPublisher(sessions)
    owner = tenancy.create_principal(
        issuer="https://synthetic-idp.invalid",
        subject="release-owner",
        kind="human",
        display_name="Release Owner",
    )
    release_publisher = tenancy.create_principal(
        issuer="lucy://synthetic/public-projection",
        subject="publisher-v1",
        kind="service",
        display_name="Release Publisher",
    )
    release_approver = tenancy.create_principal(
        issuer="lucy://synthetic/public-projection",
        subject="approver-v1",
        kind="human",
        display_name="Release Approver",
    )
    foundation = _foundation(tenancy, "utopia", "www.utopiahomes.com")
    tenancy.grant_workspace_membership(
        principal_id=owner, workspace_id=foundation.workspace_id, role="owner"
    )
    tenancy.grant_workspace_membership(
        principal_id=release_publisher,
        workspace_id=foundation.workspace_id,
        role="publisher",
    )
    tenancy.grant_workspace_membership(
        principal_id=release_approver,
        workspace_id=foundation.workspace_id,
        role="approver",
    )
    current_candidate, current_digest = publisher.stage(
        channel_binding_id=foundation.channel_binding_id,
        actor_id=owner,
        entries=[
            {
                "question": "Where is Utopia Homes located?",
                "answer": "At the Jersey Shore.",
                "source": "https://www.utopiahomes.com/about",
            }
        ],
    )
    publisher.approve(
        candidate_id=current_candidate,
        expected_digest=current_digest,
        actor_id=owner,
    )
    current_version_id = publisher.publish(candidate_id=current_candidate, actor_id=owner)

    snapshot = knowledge_snapshot(
        [
            {
                "id": "utopia-about",
                "service_line": "general",
                "kind": "description",
                "title": "Utopia Homes",
                "approved_text": "Utopia Homes creates distinctive group stays.",
                "topics": ["about"],
                "route": "about",
                "source": {
                    "id": "utopia-about-source",
                    "label": "About Utopia Homes",
                    "href": "https://www.utopiahomes.com/about",
                },
                "effective_from": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                "direct_answer": True,
            }
        ]
    )
    release_id = uuid4()
    candidate_id = uuid4()
    approval_id = uuid4()
    version_id = uuid4()
    common = {
        "source_commit": "a" * 40,
        "decision_id": "synthetic-public-release",
        "release_id": release_id,
        "realm_slug": "utopia",
        "storage_epoch": uuid4(),
        "channel_binding_id": foundation.channel_binding_id,
        "hostname": "www.utopiahomes.com",
        "candidate_id": candidate_id,
        "snapshot_digest": snapshot_digest(snapshot),
        "expected_active_version_id": current_version_id,
        "expected_active_version": 1,
        "expected_active_digest": current_digest,
        "authorized_at": datetime.now(UTC),
    }

    def config_for(
        action: str,
        *,
        actor_id: object,
        transition_id: object,
    ) -> PublicKnowledgeReleaseConfig:
        manifest = PublicKnowledgeReleaseManifestV1.model_validate(
            common
            | {
                "action": action,
                "schema_revision": (
                    "0057_public_conversation"
                    if action == "activate"
                    else "0056_memory_import_budget"
                ),
                "actor_id": actor_id,
                "transition_id": transition_id,
                "approval_id": approval_id if action in {"approve", "activate"} else None,
                "version_id": version_id if action == "activate" else None,
            }
        )
        return PublicKnowledgeReleaseConfig(
            migration_url=make_url(OWNER_DATABASE_URL),
            manifest=manifest,
            snapshot=snapshot,
        )

    stage = config_for("stage", actor_id=release_publisher, transition_id=uuid4())
    approve = config_for("approve", actor_id=release_approver, transition_id=uuid4())
    activate = config_for("activate", actor_id=release_publisher, transition_id=uuid4())
    unauthorized = config_for("approve", actor_id=release_publisher, transition_id=uuid4())
    owner_url = make_url(OWNER_DATABASE_URL).set(drivername="postgresql")
    with psycopg.connect(owner_url.render_as_string(hide_password=False)) as connection:
        assert _stage(connection, stage) is False
        connection.commit()
        assert _stage(connection, stage) is True
        with pytest.raises(PublicKnowledgeReleaseError, match="authority"):
            _approve(connection, unauthorized)
        connection.rollback()
        assert _approve(connection, approve) is False
        connection.commit()
        assert _approve(connection, approve) is True
        assert _activate(connection, activate) is False
        connection.commit()
        assert _activate(connection, activate) is True
        assert _stage(connection, stage) is True
        assert _approve(connection, approve) is True
        active = connection.execute(
            "SELECT v.id,v.version,v.snapshot_digest FROM lucy.public_projection_routes r "
            "JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
            "WHERE r.channel_binding_id=%s",
            (foundation.channel_binding_id,),
        ).fetchone()
    assert active == (version_id, 2, snapshot_digest(snapshot))


def test_database_enforces_one_wallet_per_node_and_immutable_tenure() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    foundation = _foundation(TenancyService(sessions), "utopia", "utopiahomes.test")
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            WalletRegistrationRow(
                id=uuid4(),
                node_id=foundation.node_id,
                tenure_id=foundation.tenure_id,
                status="REGISTERED_NONSPENDABLE",
                created_at=datetime.now(UTC),
            )
        )
    assert OWNER_DATABASE_URL is not None
    owner_sessions = create_session_factory(OWNER_DATABASE_URL)
    with pytest.raises(DBAPIError, match="append-only"), owner_sessions.begin() as session:
        session.execute(
            text("UPDATE lucy.node_tenures SET sequence=2 WHERE id=:id"),
            {"id": foundation.tenure_id},
        )


def test_initial_topology_has_five_nodes_four_accounts_and_isolated_realms() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    tenancy = TenancyService(sessions)
    specifications = (
        ("raymond", "Raymond", "raymond", "Raymond DeLuca", "person", "raymond.test"),
        ("utopia", "Utopia", "utopia", "Utopia Homes", "organization", "utopia.test"),
        ("platform", "Platform", "consulting", "SC Consulting", "organization", "sc.test"),
        ("platform", "Platform", "service", "Cloud Lucy Service", "service", "lucy.test"),
        ("alpha", "Alpha", "alpha", "Client Alpha", "organization", "alpha.test"),
    )
    foundations = [
        tenancy.create_node_foundation(
            account_slug=account_slug,
            account_name=account_name,
            node_slug=node_slug,
            node_name=node_name,
            node_kind=node_kind,
            realm_slug=f"{node_slug}-realm",
            workspace_slug="website",
            hostname=hostname,
        )
        for account_slug, account_name, node_slug, node_name, node_kind, hostname in specifications
    ]
    with sessions() as session:
        assert session.query(TenantAccountRow).count() == 4
        assert session.query(SecurityRealmRow).count() == 5
        assert session.query(WalletRegistrationRow).count() == 5
    assert len({item.realm_id for item in foundations}) == 5
    assert len({item.wallet_id for item in foundations}) == 5
