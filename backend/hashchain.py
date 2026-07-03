"""
LUMENCHAIN — Hash-Chain Ledger
--------------------------------
This is NOT a distributed blockchain network. It is a cryptographic
hash-chain (the same core primitive blockchains are built on): every
ledger entry embeds the SHA-256 hash of the entry before it, so any
retroactive edit to any past log breaks every hash that follows it.

This is an honest and accurate description of what this module does.
For deployments that want anchoring to a public chain (e.g. for
independent, third-party-verifiable timestamping), see the
`anchor_to_external_chain()` stub at the bottom — left unimplemented
here since that requires a real wallet/RPC endpoint and gas budget
that belongs to whoever deploys this, not something to fake.
"""

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional


GENESIS_HASH = "0" * 64


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical_json(obj: dict) -> str:
    """Deterministic JSON serialization so the same log always hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


@dataclass
class Block:
    index: int
    timestamp: float
    case_id: str
    log_hash: str          # SHA-256 of the raw log payload
    prev_block_hash: str   # hash of previous block (chain link)
    block_hash: str        # SHA-256 of this block's own contents
    metadata: dict


class HashChain:
    """
    In-memory + DB-backed hash chain. The DB is the source of truth;
    this class rebuilds/validates the in-memory view from it.
    """

    def __init__(self, db):
        self.db = db

    def _compute_block_hash(self, index, timestamp, case_id, log_hash, prev_block_hash) -> str:
        payload = canonical_json({
            "index": index,
            "timestamp": timestamp,
            "case_id": case_id,
            "log_hash": log_hash,
            "prev_block_hash": prev_block_hash,
        })
        return sha256_hex(payload)

    def add_entry(self, case_id: str, raw_log: dict, metadata: Optional[dict] = None) -> Block:
        """Hash a log entry and append it to the chain."""
        metadata = metadata or {}
        last = self.db.get_last_block()
        index = 0 if last is None else last["idx"] + 1
        prev_hash = GENESIS_HASH if last is None else last["block_hash"]

        log_hash = sha256_hex(canonical_json(raw_log))
        timestamp = time.time()
        block_hash = self._compute_block_hash(index, timestamp, case_id, log_hash, prev_hash)

        block = Block(
            index=index,
            timestamp=timestamp,
            case_id=case_id,
            log_hash=log_hash,
            prev_block_hash=prev_hash,
            block_hash=block_hash,
            metadata=metadata,
        )
        self.db.insert_block(asdict(block))
        return block

    def verify_chain(self, case_id: Optional[str] = None) -> dict:
        """
        Recomputes every block hash from stored data and checks the chain
        links. Returns a report identifying the FIRST point of divergence,
        if any — that's the earliest evidence any tampering could have
        occurred.
        """
        blocks = self.db.get_all_blocks(case_id=case_id)
        if not blocks:
            return {"valid": True, "blocks_checked": 0, "first_break_index": None, "details": "No blocks to verify."}

        prev_hash = GENESIS_HASH
        for b in blocks:
            expected_block_hash = self._compute_block_hash(
                b["index"], b["timestamp"], b["case_id"], b["log_hash"], prev_hash
            )
            if b["prev_block_hash"] != prev_hash or b["block_hash"] != expected_block_hash:
                return {
                    "valid": False,
                    "blocks_checked": len(blocks),
                    "first_break_index": b["index"],
                    "details": f"Chain integrity broken at block {b['index']}. "
                               f"Stored block_hash does not match recomputed hash — "
                               f"this block or an earlier one was altered after being written.",
                }
            prev_hash = b["block_hash"]

        return {"valid": True, "blocks_checked": len(blocks), "first_break_index": None, "details": "Chain intact. No tampering detected."}

    def verify_single_log(self, case_id: str, raw_log: dict, block_index: int) -> dict:
        """Check whether a specific piece of evidence still matches its recorded hash."""
        block = self.db.get_block(case_id, block_index)
        if not block:
            return {"found": False, "matches": False}
        current_hash = sha256_hex(canonical_json(raw_log))
        return {
            "found": True,
            "matches": current_hash == block["log_hash"],
            "recorded_hash": block["log_hash"],
            "recomputed_hash": current_hash,
        }

    def anchor_to_external_chain(self, block_hash: str):
        """
        Stub: in a production deployment, this is where you'd submit
        `block_hash` (e.g. batched via a Merkle root) to a public chain
        or a timestamping authority (RFC 3161 TSA) for independent,
        third-party-verifiable proof-of-existence. Left unimplemented —
        wire this to your org's actual RPC/TSA endpoint and credentials.
        """
        raise NotImplementedError(
            "External anchoring requires a real blockchain RPC endpoint or "
            "RFC 3161 timestamp authority — configure one for your deployment."
        )
