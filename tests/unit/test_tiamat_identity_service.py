from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from lucy.tiamat_identity_service import app, log_assumed_aws_identity


def test_identity_service_is_content_free_and_dispatch_disabled() -> None:
    with patch("lucy.tiamat_identity_service.boto3.client") as client:
        client.return_value.get_caller_identity.return_value = {
            "Arn": "arn:aws:sts::429870640638:assumed-role/test/session",
            "Account": "429870640638",
            "UserId": "AROATEST",
        }
        with TestClient(app) as test_client:
            response = test_client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {"status": "disabled", "provider_dispatch": False}
    assert response.headers["cache-control"] == "no-store"
    assert TestClient(app).post("/execution/v1/inference").status_code == 404
    assert TestClient(app).get("/docs").status_code == 404


def test_startup_logs_the_assumed_role_arn(caplog) -> None:  # type: ignore[no-untyped-def]
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:sts::429870640638:assumed-role/tiamat-staging-executor/session",
        "Account": "429870640638",
        "UserId": "AROAEXAMPLE:session",
    }
    with (
        patch("lucy.tiamat_identity_service.boto3.client", return_value=fake_sts),
        caplog.at_level("INFO", logger="lucy.tiamat_identity_service"),
        TestClient(app),
    ):
        pass

    assert any(
        "tiamat_identity_service_sts_check_ok" in record.message
        and "tiamat-staging-executor" in record.message
        for record in caplog.records
    )


def test_startup_identity_check_failure_is_logged_and_not_raised(caplog) -> None:  # type: ignore[no-untyped-def]
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity")
    with (
        patch("lucy.tiamat_identity_service.boto3.client", side_effect=error),
        caplog.at_level("WARNING", logger="lucy.tiamat_identity_service"),
        TestClient(app) as test_client,
    ):
        response = test_client.get("/healthz")

    assert response.status_code == 503
    assert any(
        "tiamat_identity_service_sts_check_failed" in record.message for record in caplog.records
    )


def test_log_assumed_aws_identity_never_raises_on_botocore_error() -> None:
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity")
    with patch("lucy.tiamat_identity_service.boto3.client", side_effect=error):
        log_assumed_aws_identity()  # must not raise
