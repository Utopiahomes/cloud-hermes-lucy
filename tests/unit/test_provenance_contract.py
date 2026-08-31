from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from lucy.provenance import MAX_SOURCES, DerivationSourcesV1


def test_provenance_contract_is_canonical_and_content_free() -> None:
    a, b = sorted((uuid4(), uuid4()))
    manifest = DerivationSourcesV1(source_evidence_ids=(b, a, b))
    assert manifest.source_evidence_ids == (a, b)
    assert manifest.model_dump(mode="json") == {"source_evidence_ids": [str(a), str(b)]}
    with pytest.raises(ValidationError):
        manifest.source_evidence_ids = ()


@pytest.mark.parametrize("values", [["not-an-evidence-id"], [None], [True]])
def test_provenance_contract_rejects_invalid_ids(values: list[object]) -> None:
    with pytest.raises(ValidationError):
        DerivationSourcesV1.model_validate({"source_evidence_ids": values})


def test_provenance_contract_rejects_silent_truncation() -> None:
    with pytest.raises(ValidationError):
        DerivationSourcesV1(source_evidence_ids=tuple(UUID(int=i) for i in range(MAX_SOURCES + 1)))


def test_provenance_contract_rejects_embedded_content_or_authority() -> None:
    with pytest.raises(ValidationError):
        DerivationSourcesV1.model_validate({"source_evidence_ids": [], "owner_approved": True})
