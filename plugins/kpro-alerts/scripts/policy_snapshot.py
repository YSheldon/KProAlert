"""Strict validation for KProSvc native snapshot stdout.

This module is a parser at the trusted native-adapter boundary.  The JSON is
external input and is never treated as native authority; callers must obtain
it from the intended adapter invocation and provide the invocation bindings.
"""

import json
import math
import re


SCHEMA = "FalconProPolicySnapshot/v1"
MAX_RAW_BYTES = 4096
FILETIME_TICKS_PER_SECOND = 10_000_000
FILETIME_EPOCH_OFFSET_SECONDS = 11_644_473_600
SNAPSHOT_OPERATION = 1
VERIFY_OPERATION = 2
SNAPSHOT_TTL_SECONDS = 30.0
# FILETIME is produced by the service clock while started_at/now come from the
# adapter clock.  One second is the only tolerated clock/measurement skew.
START_TIME_TOLERANCE_SECONDS = 1.0
MAX_U32 = 0xFFFFFFFF
MAX_U64 = 0xFFFFFFFFFFFFFFFF

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_DECIMAL_U64 = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_OUTPUT_KEYS = frozenset(
    {
        "schema",
        "success",
        "hr",
        "status",
        "operation",
        "servicePid",
        "requestId",
        "transactionId",
        "observedAtFileTime",
        "expectedDigestSha256",
        "digestSha256",
        "policyFileSha256",
        "runtimeFileSha256",
        "deviceSha256",
        "policyVersion",
        "policyFlags",
    }
)


class SnapshotValidationError(ValueError):
    """Raised when native stdout or its invocation binding is invalid."""


def _duplicate_rejecting_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SnapshotValidationError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(value):
    raise SnapshotValidationError("NaN and Infinity are not permitted")


def _parse_canonical_int(value):
    if value == "-0" or (len(value) > 1 and value[0] == "0"):
        raise SnapshotValidationError("non-canonical JSON integer")
    if value.startswith("-") and len(value) > 2 and value[1] == "0":
        raise SnapshotValidationError("non-canonical JSON integer")
    return int(value)


def _parse_raw(raw):
    if type(raw) is not bytes:
        raise SnapshotValidationError("stdout must be bytes")
    if not raw or len(raw) > MAX_RAW_BYTES:
        raise SnapshotValidationError("stdout exceeds 4096 bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_constant,
            parse_int=_parse_canonical_int,
        )
    except SnapshotValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise SnapshotValidationError("invalid JSON stdout") from error
    if type(value) is not dict:
        raise SnapshotValidationError("snapshot JSON must be an object")
    if set(value) != _OUTPUT_KEYS:
        raise SnapshotValidationError("snapshot fields do not match native schema")
    return value


def _require_hex(value, pattern, name):
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise SnapshotValidationError(f"invalid {name}")
    return value


def _require_hex_argument(value, name):
    if type(value) is not str or re.fullmatch(r"[0-9A-Fa-f]{64}\Z", value) is None:
        raise SnapshotValidationError(f"invalid {name}")
    return value.lower()


def _require_uint(value, maximum, name):
    if type(value) is not int or not 0 <= value <= maximum:
        raise SnapshotValidationError(f"invalid {name}")
    return value


def _require_u64_string(value, name):
    if type(value) is not str or _DECIMAL_U64.fullmatch(value) is None:
        raise SnapshotValidationError(f"invalid {name}")
    number = int(value)
    if number > MAX_U64 or str(number) != value:
        raise SnapshotValidationError(f"invalid {name}")
    return number


def _require_seconds(value, name):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise SnapshotValidationError(f"invalid {name}")
    if value < 0:
        raise SnapshotValidationError(f"invalid {name}")
    return float(value)


def parse_snapshot(
    raw: bytes,
    *,
    exit_code,
    transaction_id,
    device_id,
    service_pid,
    expected_digest=None,
    started_at,
    now,
) -> dict:
    """Validate one KProSvc ``FalconProPolicySnapshot/v1`` stdout record.

    ``started_at`` and ``now`` are Unix seconds supplied by the native adapter
    caller.  ``observedAtFileTime`` is accepted within 30 seconds of ``now``;
    a one-second skew is allowed at both the invocation-start and current-time
    boundaries, as exposed by :data:`START_TIME_TOLERANCE_SECONDS`.

    ``expected_digest`` selects the operation: ``None`` means SNAPSHOT and
    requires an all-zero expected digest; a 64-hex value means VERIFY and must
    match both the native expected and returned digest fields.
    """
    payload = _parse_raw(raw)

    if type(exit_code) is not int or exit_code != 0:
        raise SnapshotValidationError("native adapter exit code is not zero")
    transaction = _require_hex_argument(transaction_id, "transaction_id")
    device = _require_hex_argument(device_id, "device_id")
    pid = _require_uint(service_pid, MAX_U32, "service_pid")
    if pid == 0:
        raise SnapshotValidationError("service_pid must be positive")
    started = _require_seconds(started_at, "started_at")
    current = _require_seconds(now, "now")
    if current < started:
        raise SnapshotValidationError("now precedes started_at")

    if payload["schema"] != SCHEMA:
        raise SnapshotValidationError("unknown snapshot schema")
    if type(payload["success"]) is not bool or payload["success"] is not True:
        raise SnapshotValidationError("native snapshot did not succeed")
    if type(payload["hr"]) is not int or payload["hr"] != 0:
        raise SnapshotValidationError("native snapshot HRESULT is not zero")
    if type(payload["status"]) is not int or payload["status"] != 0:
        raise SnapshotValidationError("native snapshot status is not zero")

    operation = payload["operation"]
    if type(operation) is not int or operation not in (SNAPSHOT_OPERATION, VERIFY_OPERATION):
        raise SnapshotValidationError("invalid snapshot operation")
    if type(payload["servicePid"]) is not int or not 0 < payload["servicePid"] <= MAX_U32:
        raise SnapshotValidationError("invalid native service PID")
    if payload["servicePid"] != pid:
        raise SnapshotValidationError("service PID binding mismatch")

    _require_hex(payload["requestId"], _HEX32, "requestId")
    if payload["transactionId"] != transaction:
        raise SnapshotValidationError("transaction binding mismatch")
    _require_hex(payload["transactionId"], _HEX64, "transactionId")
    if payload["deviceSha256"] != device:
        raise SnapshotValidationError("device digest binding mismatch")

    observed_filetime = _require_u64_string(
        payload["observedAtFileTime"], "observedAtFileTime"
    )
    observed = observed_filetime / FILETIME_TICKS_PER_SECOND - FILETIME_EPOCH_OFFSET_SECONDS
    if observed < started - START_TIME_TOLERANCE_SECONDS:
        raise SnapshotValidationError("snapshot predates adapter invocation")
    if observed > current + START_TIME_TOLERANCE_SECONDS:
        raise SnapshotValidationError("snapshot timestamp is from the future")
    if current - observed > SNAPSHOT_TTL_SECONDS:
        raise SnapshotValidationError("snapshot response is stale")

    expected_output = payload["expectedDigestSha256"]
    returned_digest = payload["digestSha256"]
    _require_hex(expected_output, _HEX64, "expectedDigestSha256")
    _require_hex(returned_digest, _HEX64, "digestSha256")
    _require_hex(payload["policyFileSha256"], _HEX64, "policyFileSha256")
    _require_hex(payload["runtimeFileSha256"], _HEX64, "runtimeFileSha256")
    _require_hex(payload["deviceSha256"], _HEX64, "deviceSha256")

    if expected_digest is None:
        if operation != SNAPSHOT_OPERATION or expected_output != "0" * 64:
            raise SnapshotValidationError("snapshot expected digest must be zero")
    else:
        expected = _require_hex_argument(expected_digest, "expected_digest")
        if operation != VERIFY_OPERATION or expected_output != expected or returned_digest != expected:
            raise SnapshotValidationError("verify digest binding mismatch")

    _require_u64_string(payload["policyVersion"], "policyVersion")
    _require_uint(payload["policyFlags"], MAX_U32, "policyFlags")
    return dict(payload)


__all__ = [
    "FILETIME_EPOCH_OFFSET_SECONDS",
    "FILETIME_TICKS_PER_SECOND",
    "MAX_RAW_BYTES",
    "SNAPSHOT_OPERATION",
    "SNAPSHOT_TTL_SECONDS",
    "START_TIME_TOLERANCE_SECONDS",
    "SnapshotValidationError",
    "VERIFY_OPERATION",
    "parse_snapshot",
]
