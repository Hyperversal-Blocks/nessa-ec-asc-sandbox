#!/usr/bin/env python3
"""
Local JSON cache for multi-actor use-case story runs.

Keeps named actors (holder, verifier, delegatee, issuer) so the same narrative can be
re-run with bumped epochs/counters while staying deterministic when combined with
fixed seeds derived from run_counter + step ids.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from artifact_layout import USECASE_ACTOR_CACHE_PATH

CACHE_VERSION = 1
DEFAULT_CACHE_FILENAME = "nessa_usecase_actors.json"
DEFAULT_CACHE_PATH = USECASE_ACTOR_CACHE_PATH


def default_cache_document() -> dict[str, Any]:
    # Simplified preset cast for demos; edit the file to experiment.
    return {
        "version": CACHE_VERSION,
        "run_counter": 0,
        "actors": {
            "alice": {
                "display_name": "Alice (primary holder)",
                "role": "holder",
                "session_pk_label": "pk:alice/session/laptop-7",
                "rp_id": "rp://payments.example",
                "policy_flags": 3,
            },
            "bob": {
                "display_name": "Bob (verifier gateway)",
                "role": "verifier",
                "verifies_rp": "rp://payments.example",
            },
            "charlie": {
                "display_name": "Charlie (delegated device)",
                "role": "delegatee",
                "child_pk_label": "pk:charlie/session/phone-2",
                "scope_bits": 15,
                "valid_from": 1,
                "valid_until": 4000000000,
            },
            "dana": {
                "display_name": "Dana (credential issuer)",
                "role": "issuer",
                "credential_root_label": "cred-root:issuer-dana-v1",
                "age_band": 25,
                "region_code": 840,
                "role_flags": 5,
                "predicate_selector": 2,
            },
            "eve": {
                "display_name": "Eve (TLS / OAuth peer)",
                "role": "tls_peer",
                "sni_or_server_id": "svc.payments.example",
                "transcript_label": "tls:hs:alice-to-payments",
                "ephemeral_key_label": "ek:alice-handshake",
                "client_binding_tag": "oauth:state-alice-001",
            },
        },
        "history": [],
    }


def cache_path_from_arg(path: str | Path | None) -> Path:
    if path is None:
        return DEFAULT_CACHE_PATH
    return Path(path)


def load_actor_cache(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"actor cache not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("version") != CACHE_VERSION:
        raise ValueError(f"unsupported cache version {raw.get('version')!r}; expected {CACHE_VERSION}")
    if "actors" not in raw or not isinstance(raw["actors"], dict):
        raise ValueError("cache missing actors map")
    raw.setdefault("run_counter", 0)
    raw.setdefault("history", [])
    return raw


def save_actor_cache(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def init_actor_cache(path: Path, *, overwrite: bool = False) -> dict[str, Any]:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to clobber existing cache: {path}")
    doc = default_cache_document()
    save_actor_cache(path, doc)
    return doc


def _actor(doc: dict[str, Any], actor_id: str) -> dict[str, Any]:
    actors = doc["actors"]
    if actor_id not in actors:
        raise KeyError(f"unknown actor {actor_id!r}; known: {sorted(actors)}")
    row = actors[actor_id]
    if not isinstance(row, dict):
        raise TypeError(f"actor {actor_id} must be an object")
    return row


def _rp_consistent(doc: dict[str, Any]) -> bool:
    alice = _actor(doc, "alice")
    bob = _actor(doc, "bob")
    return alice.get("rp_id") == bob.get("verifies_rp")


# (json_key, human prompt, "int" | "str")
ACTOR_INTERACTIVE_FIELDS: dict[str, list[tuple[str, str, str]]] = {
    "alice": [
        ("display_name", "Display name for this holder", "str"),
        ("session_pk_label", "Session public key label (hash recommended)", "str"),
        ("rp_id", "Relying party / app id Alice uses at login", "str"),
        ("policy_flags", "Policy flags (32-bit integer)", "int"),
    ],
    "bob": [
        ("display_name", "Display name for verifier", "str"),
        ("verifies_rp", "RP id Bob’s gateway expects (should match Alice’s rp_id)", "str"),
    ],
    "charlie": [
        ("display_name", "Display name for delegatee device", "str"),
        ("child_pk_label", "Child / delegated device public key label", "str"),
        ("scope_bits", "Capability bitmask (integer)", "int"),
        ("valid_from", "Validity window start (32-bit slot)", "int"),
        ("valid_until", "Validity window end (32-bit slot)", "int"),
    ],
    "dana": [
        ("display_name", "Display name for issuer", "str"),
        ("credential_root_label", "Credential / Merkle root label", "str"),
        ("age_band", "Age band code (integer)", "int"),
        ("region_code", "Region code (integer)", "int"),
        ("role_flags", "Role bitmask (integer)", "int"),
        ("predicate_selector", "Predicate selector (integer)", "int"),
    ],
    "eve": [
        ("display_name", "Display name for TLS/OAuth peer", "str"),
        ("transcript_label", "Handshake transcript label", "str"),
        ("sni_or_server_id", "Server name / id user expects", "str"),
        ("ephemeral_key_label", "Ephemeral key fingerprint label", "str"),
        ("client_binding_tag", "OAuth state or binding tag", "str"),
    ],
}


def prompt_actor_cache_interactive(
    doc: dict[str, Any],
    path: Path,
    *,
    input_func=input,
    print_func=print,
) -> None:
    """
    Prompt at the terminal for each actor’s fields; empty input keeps the cached value.
    Writes the JSON file after all actors are reviewed.
    """
    print_func(
        "\n=== Interactive actor setup (multiple users / roles) ===\n"
        "Each person at the keyboard enters values for their role. "
        "Press Enter alone to keep the bracketed default from the cache file.\n"
    )
    for actor_id, field_specs in ACTOR_INTERACTIVE_FIELDS.items():
        row = _actor(doc, actor_id)
        role = row.get("role", actor_id)
        dn = row.get("display_name", actor_id)
        print_func(f"\n--- {dn} [id={actor_id}, role={role}] ---")
        print_func(f"    ({'Holder proves login' if actor_id == 'alice' else 'Verifier checks proofs' if actor_id == 'bob' else 'Other story participant'})")
        for key, label, kind in field_specs:
            cur = row.get(key, "" if kind == "str" else 0)
            raw = input_func(f"  {label}\n    [{cur}]: ").strip()
            if not raw:
                continue
            if kind == "int":
                try:
                    row[key] = int(raw, 0)
                except ValueError:
                    print_func(f"    (ignored non-integer; keeping {cur!r})")
            else:
                row[key] = raw

    if not _rp_consistent(doc):
        print_func(
            "\n  WARNING: alice.rp_id != bob.verifies_rp — Bob will flag RP mismatch in the story summary.\n"
            "  Fix now? [y/N]: "
        )
        fix = input_func().strip().lower()
        if fix == "y":
            arp = _actor(doc, "alice").get("rp_id", "")
            sync = input_func(f"  Set bob.verifies_rp to match alice ({arp!r})? [Y/n]: ").strip().lower()
            if sync != "n":
                _actor(doc, "bob")["verifies_rp"] = arp
                print_func("  bob.verifies_rp updated.")
    save_actor_cache(path, doc)
    print_func(f"\nSaved updated actors to {path.resolve()}\n")
