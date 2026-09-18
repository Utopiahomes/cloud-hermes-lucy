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


def test_startup_prints_the_assumed_role_arn(capsys) -> None:  # type: ignore[no-untyped-def]
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:sts::429870640638:assumed-role/tiamat-staging-executor/session",
        "Account": "429870640638",
        "UserId": "AROAEXAMPLE:session",
    }
    with (
        patch("lucy.tiamat_identity_service.boto3.client", return_value=fake_sts),
        TestClient(app),
    ):
        pass

    out = capsys.readouterr().out
    assert "tiamat_identity_service_sts_check_ok" in out
    assert "tiamat-staging-executor" in out


def test_startup_identity_check_failure_is_printed_and_not_raised(capsys) -> None:  # type: ignore[no-untyped-def]
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity")
    with (
        patch("lucy.tiamat_identity_service.boto3.client", side_effect=error),
        TestClient(app) as test_client,
    ):
        response = test_client.get("/healthz")

    assert response.status_code == 503
    assert "tiamat_identity_service_sts_check_failed" in capsys.readouterr().out


def test_log_assumed_aws_identity_never_raises_on_botocore_error() -> None:
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity")
    with patch("lucy.tiamat_identity_service.boto3.client", side_effect=error):
        log_assumed_aws_identity()  # must not raise
