import json
import unittest

from policy_snapshot import (
    FILETIME_EPOCH_OFFSET_SECONDS,
    FILETIME_TICKS_PER_SECOND,
    START_TIME_TOLERANCE_SECONDS,
    SnapshotValidationError,
    parse_snapshot,
)


STARTED = 1_700_000_000
NOW = STARTED + 5
TRANSACTION = "a" * 64
DEVICE = "e" * 64
PID = 4321
ZERO_DIGEST = "0" * 64
RETURNED_DIGEST = "b" * 64


def filetime(unix_seconds):
    return str(int((unix_seconds + FILETIME_EPOCH_OFFSET_SECONDS) * FILETIME_TICKS_PER_SECOND))


def snapshot_payload(operation=1, expected=ZERO_DIGEST, digest=RETURNED_DIGEST):
    return {
        "schema": "FalconProPolicySnapshot/v1",
        "success": True,
        "hr": 0,
        "status": 0,
        "operation": operation,
        "servicePid": PID,
        "requestId": "1" * 32,
        "transactionId": TRANSACTION,
        "observedAtFileTime": filetime(STARTED + 4),
        "expectedDigestSha256": expected,
        "digestSha256": digest,
        "policyFileSha256": "c" * 64,
        "runtimeFileSha256": "d" * 64,
        "deviceSha256": DEVICE,
        "policyVersion": "18446744073709551615",
        "policyFlags": 0xFFFFFFFF,
    }


def raw_json(payload):
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


class PolicySnapshotTests(unittest.TestCase):
    def parse(self, payload=None, **kwargs):
        payload = snapshot_payload() if payload is None else payload
        arguments = dict(
            exit_code=0,
            transaction_id=TRANSACTION,
            device_id=DEVICE,
            service_pid=PID,
            expected_digest=None,
            started_at=STARTED,
            now=NOW,
        )
        arguments.update(kwargs)
        return parse_snapshot(raw_json(payload), **arguments)

    def test_accepts_native_snapshot_and_preserves_exact_fields(self):
        result = self.parse()
        self.assertEqual(result, snapshot_payload())

    def test_accepts_native_verify_only_when_expected_and_returned_digest_match(self):
        expected = RETURNED_DIGEST
        payload = snapshot_payload(operation=2, expected=expected, digest=expected)
        result = self.parse(payload, expected_digest=expected)
        self.assertEqual(result["operation"], 2)

    def test_binds_transaction_device_and_service_pid_to_invocation(self):
        for field, value in (
            ("transaction_id", "f" * 64),
            ("device_id", "f" * 64),
            ("service_pid", PID + 1),
        ):
            with self.subTest(field=field):
                with self.assertRaises(SnapshotValidationError):
                    self.parse(**{field: value})

    def test_rejects_nonzero_exit_or_native_status(self):
        with self.assertRaises(SnapshotValidationError):
            self.parse(exit_code=1)
        for field in ("success", "hr", "status"):
            payload = snapshot_payload()
            payload[field] = False if field == "success" else 1
            with self.subTest(field=field):
                with self.assertRaises(SnapshotValidationError):
                    self.parse(payload)

    def test_rejects_duplicate_and_extra_json_fields(self):
        duplicate = b'{"schema":"FalconProPolicySnapshot/v1","schema":"other"}'
        with self.assertRaises(SnapshotValidationError):
            parse_snapshot(
                duplicate,
                exit_code=0,
                transaction_id=TRANSACTION,
                device_id=DEVICE,
                service_pid=PID,
                started_at=STARTED,
                now=NOW,
            )
        payload = snapshot_payload()
        payload["extra"] = 1
        with self.assertRaises(SnapshotValidationError):
            self.parse(payload)

    def test_rejects_nan_boolean_pseudo_integer_and_oversize_json(self):
        payload = snapshot_payload()
        payload["policyFlags"] = True
        with self.assertRaises(SnapshotValidationError):
            self.parse(payload)

        nan_payload = raw_json(snapshot_payload()).replace(
            b'"policyFlags":4294967295', b'"policyFlags":NaN'
        )
        with self.assertRaises(SnapshotValidationError):
            parse_snapshot(
                nan_payload,
                exit_code=0,
                transaction_id=TRANSACTION,
                device_id=DEVICE,
                service_pid=PID,
                started_at=STARTED,
                now=NOW,
            )

        oversized = raw_json(snapshot_payload()) + b" " * 4096
        with self.assertRaises(SnapshotValidationError):
            self.parse_bytes(oversized)

    def parse_bytes(self, raw, **kwargs):
        arguments = dict(
            exit_code=0,
            transaction_id=TRANSACTION,
            device_id=DEVICE,
            service_pid=PID,
            expected_digest=None,
            started_at=STARTED,
            now=NOW,
        )
        arguments.update(kwargs)
        return parse_snapshot(raw, **arguments)

    def test_snapshot_and_verify_digest_rules(self):
        with self.assertRaises(SnapshotValidationError):
            self.parse(snapshot_payload(expected=RETURNED_DIGEST))
        with self.assertRaises(SnapshotValidationError):
            self.parse(snapshot_payload(operation=2, expected=RETURNED_DIGEST, digest=RETURNED_DIGEST))
        with self.assertRaises(SnapshotValidationError):
            self.parse(
                snapshot_payload(operation=2, expected=RETURNED_DIGEST, digest=RETURNED_DIGEST),
                expected_digest="f" * 64,
            )
        with self.assertRaises(SnapshotValidationError):
            self.parse(
                snapshot_payload(operation=2, expected=RETURNED_DIGEST, digest="f" * 64),
                expected_digest=RETURNED_DIGEST,
            )

    def test_rejects_stale_early_and_far_future_filetime(self):
        for observed in (NOW - 31, STARTED - START_TIME_TOLERANCE_SECONDS - 1, NOW + 2):
            payload = snapshot_payload()
            payload["observedAtFileTime"] = filetime(observed)
            with self.subTest(observed=observed):
                with self.assertRaises(SnapshotValidationError):
                    self.parse(payload)

        payload = snapshot_payload()
        payload["observedAtFileTime"] = filetime(STARTED - START_TIME_TOLERANCE_SECONDS / 2)
        self.parse(payload)

    def test_rejects_invalid_policy_and_timestamp_types(self):
        invalid_values = (
            ("policyVersion", 1),
            ("policyVersion", "01"),
            ("policyVersion", "18446744073709551616"),
            ("policyFlags", -1),
            ("policyFlags", 0x100000000),
            ("observedAtFileTime", 1),
            ("observedAtFileTime", "01"),
            ("observedAtFileTime", "-1"),
        )
        for field, value in invalid_values:
            payload = snapshot_payload()
            payload[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(SnapshotValidationError):
                    self.parse(payload)

    def test_rejects_invalid_invocation_types_and_non_bytes(self):
        with self.assertRaises(SnapshotValidationError):
            self.parse(exit_code=True)
        with self.assertRaises(SnapshotValidationError):
            self.parse(service_pid=True)
        with self.assertRaises(SnapshotValidationError):
            self.parse_bytes(raw_json(snapshot_payload()).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
