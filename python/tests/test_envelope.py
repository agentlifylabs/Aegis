"""Tests for the Python event envelope and builder."""

import pytest

from aegis_sdk.envelope import Envelope, EventType, Builder


def test_builder_chain():
    b = Builder("t1", "u1", "s1")
    e0 = b.append(EventType.MODEL_CALL_STARTED, {"model_id": "gpt-4o"})
    assert e0.seq == 0
    assert e0.prev_hash is None
    assert e0.hash is not None
    assert len(e0.hash) == 32

    e1 = b.append(EventType.MODEL_CALL_FINISHED, {"finish_reason": "stop"})
    assert e1.seq == 1
    assert e1.prev_hash == e0.hash


def test_envelope_verify():
    b = Builder("t1", "u1", "s1")
    e = b.append(EventType.TOOL_CALL_PROPOSED, {"tool_name": "read_file"})
    assert e.verify()


def test_tampered_payload_fails_verify():
    b = Builder("t1", "u1", "s1")
    e = b.append(EventType.MODEL_CALL_STARTED, {"model_id": "gpt-4o"})
    original_hash = e.hash
    e.payload = {"model_id": "tampered"}
    assert not e.verify()
    e.payload = {"model_id": "gpt-4o"}
    e.hash = original_hash


def test_seq_zero_no_prev_hash():
    b = Builder("t1", "u1", "s1")
    e = b.append(EventType.MODEL_CALL_STARTED, None)
    assert e.seq == 0
    assert e.prev_hash is None


def test_builder_from_existing_seq():
    b1 = Builder("t1", "u1", "s1")
    e0 = b1.append(EventType.MODEL_CALL_STARTED, None)

    b2 = Builder("t1", "u1", "s1", next_seq=1, prev_hash=e0.hash)
    e1 = b2.append(EventType.MODEL_CALL_FINISHED, None)
    assert e1.seq == 1
    assert e1.prev_hash == e0.hash


def test_to_dict_round_trip():
    b = Builder("t1", "u1", "s1")
    e = b.append(EventType.TOOL_CALL_PROPOSED, {"tool_name": "read_file", "args": {"path": "/tmp"}})
    d = e.to_dict()
    assert d["seq"] == 0
    assert d["event_type"] == "TOOL_CALL_PROPOSED"
    assert "hash" in d
