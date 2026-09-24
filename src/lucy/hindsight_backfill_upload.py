"""Resumable local upload of approved export history to a temporary private bridge."""

from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from lucy.chatgpt_import import (
    ChatGPTExportInventoryV1,
    inventory_chatgpt_export,
    load_bounded_chatgpt_conversations,
)
from lucy.chatgpt_manifest import _parse_conversation, _quarantine_credential_like_messages
from lucy.contracts.canonical import canonical_json_bytes
from lucy.hindsight_backfill import bounded_items, eligible_messages
from lucy.hindsight_backfill_intake import BackfillBatch


def _inside(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("backfill path is outside protected intake root")
    return resolved


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _upload(endpoint: str, token: str, body: bytes) -> int:
    request = Request(
        endpoint, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with build_opener(_RejectRedirects()).open(request, timeout=600) as response:
            if response.status != 200:
                raise RuntimeError("backfill intake rejected batch")
            result = json.load(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError("backfill intake unavailable") from exc
    if not isinstance(result, dict) or result.get("accepted") is not True:
        raise RuntimeError("backfill intake response differs")
    processed = result.get("processed_count")
    if type(processed) is not int:
        raise RuntimeError("backfill intake count differs")
    return processed


def upload(
    *, intake_root: Path, zip_path: Path, inventory_path: Path,
    fingerprint_key_path: Path, token_path: Path, receipt_dir: Path,
    endpoint: str, maximum_batches: int,
) -> tuple[int, int]:
    if (not endpoint.startswith("https://") or not endpoint.endswith(
        ".onrender.com/v1/raymond/hindsight/backfill"
    )):
        raise ValueError("backfill HTTPS destination differs")
    if maximum_batches < 1:
        raise ValueError("maximum batches must be positive")
    root = intake_root.resolve()
    archive = _inside(zip_path, root)
    inventory = ChatGPTExportInventoryV1.model_validate_json(
        _inside(inventory_path, root).read_bytes()
    )
    key = _inside(fingerprint_key_path, root).read_bytes()
    current = inventory_chatgpt_export(
        archive, intake_root=root, fingerprint_key=key,
    )
    if (current.archive_commitment != inventory.archive_commitment
            or len(current.conversations) != len(inventory.conversations)
            or current.issues):
        raise ValueError("approved export inventory differs")
    token = _inside(token_path, root).read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise ValueError("backfill capability token unavailable")
    receipts = _inside(receipt_dir, root)
    receipts.mkdir(parents=True, exist_ok=True)
    raw = load_bounded_chatgpt_conversations(archive, intake_root=root)
    conversations = tuple(
        _quarantine_credential_like_messages(_parse_conversation(value))
        for value in raw if isinstance(value, dict)
    )
    messages = eligible_messages(conversations)
    uploaded_batches = 0
    uploaded_records = 0
    for index, items in enumerate(bounded_items(
        messages, archive_commitment=inventory.archive_commitment,
    ), start=1):
        batch = BackfillBatch.model_validate({
            "archive_commitment": inventory.archive_commitment,
            "items": items,
        })
        body = canonical_json_bytes(batch)
        digest = sha256(body).hexdigest()
        receipt_path = receipts / f"batch-{index:05d}.json"
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if receipt != {"batch_index": index, "digest": digest,
                           "processed_count": len(items)}:
                raise ValueError("existing backfill receipt differs")
            continue
        processed = _upload(endpoint, token, body)
        if processed != len(items):
            raise RuntimeError("backfill count differs")
        receipt = {"batch_index": index, "digest": digest,
                   "processed_count": processed}
        temporary = receipt_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(receipt_path)
        uploaded_batches += 1
        uploaded_records += processed
        print(f"BACKFILL_BATCH:{index}:{processed}", flush=True)
        if uploaded_batches >= maximum_batches:
            break
    return uploaded_batches, uploaded_records


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("intake-root", "zip-path", "inventory-path", "fingerprint-key-path",
                 "token-path", "receipt-dir"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--maximum-batches", type=int, default=1)
    args = parser.parse_args()
    batches, records = upload(
        intake_root=args.intake_root, zip_path=args.zip_path,
        inventory_path=args.inventory_path,
        fingerprint_key_path=args.fingerprint_key_path,
        token_path=args.token_path, receipt_dir=args.receipt_dir,
        endpoint=args.endpoint, maximum_batches=args.maximum_batches,
    )
    print(json.dumps({"uploaded_batches": batches, "uploaded_records": records}))


if __name__ == "__main__":
    main()
