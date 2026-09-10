"""Durable, privacy-safe notification preparation journal.

This module deliberately stops at notification drafts. It does not send mail,
call a remote service, or infer delivery from a generated draft.
"""

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
import re
import sqlite3
import time


MAX_INPUTS = 200
MAX_BASELINE_INPUTS = 2000
MAX_ID_LENGTH = 128
MAX_RECEIPT_LENGTH = 256
MAX_ENTRIES = 100000
MAX_U64 = (1 << 64) - 1
MAX_U32 = (1 << 32) - 1

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_RECEIPT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_TOKEN_RE = re.compile(r"n-[0-9a-f]{64}\Z")

# These names mirror the service's safe numeric/boolean projection. String
# values are intentionally absent; alertId is the only caller-supplied string
# accepted, and it is restricted to an identifier grammar.
SAFE_NUMERIC_FIELDS = (
    "eventType",
    "operation",
    "decisionMode",
    "processId",
    "policyVersion",
    "sequence",
    "correlationId",
    "processCreateTime",
    "flags",
    "actionStatus",
    "droppedCount",
    "pathLengthBytes",
    "pathOriginalLengthBytes",
    "cmdlineLengthBytes",
    "cmdlineOriginalLengthBytes",
    "processImagePathLengthBytes",
    "processImagePathOriginalLengthBytes",
    "ransomwareSignals",
    "eventCount",
    "blockedCount",
    "terminatedCount",
    "expectedFileFormat",
    "detectedFileFormat",
    "formatConfidence",
    "renameBurstCount",
    "parentProcessId",
    "parentProcessCreateTime",
    "processClassFlags",
    "behaviorRuleId",
    "behaviorWindowMs",
    "behaviorSignals",
    "uniqueFileCount",
    "distinctDirectoryCount",
    "writeCount",
    "newFileWriteCount",
    "overwriteCount",
    "renameCount",
    "deleteCount",
    "truncateCount",
    "extensionChangeCount",
    "bytesWritten",
    "destructiveFamilyCount",
    "behaviorReserved",
)

SAFE_BOOLEAN_FIELDS = (
    "reportOnly",
    "pathTruncated",
    "cmdlineTrusted",
    "cmdlineTruncated",
    "processImagePathTrusted",
    "processImagePathTruncated",
    "directDiskMbr",
    "directDiskMbrContentChanged",
    "directDiskMbrInspectionUnavailable",
    "directDiskMbrF1Exempt",
    "directDiskMbrHashExempt",
    "ransomwareFormatMismatch",
    "ransomwareSuspiciousRename",
    "ransomwareSuspiciousCreate",
    "ransomwareDirectCreate",
    "ransomwareRansomNote",
    "ransomwareLongFileName",
    "ransomwareHashLikeFileName",
    "ransomwareHighAnomalyFileName",
    "ransomwareDisguisedDoubleExtension",
    "ransomwareSuspiciousUnicode",
    "ransomwareElfImage",
    "ransomwareFirstObserved",
    "ransomwareRecentProcess",
    "ransomwareRenameBurst",
    "ransomwareDirectoryRecentThreat",
    "ransomwareBlocked",
    "ransomwareRiskBlocked",
    "ransomwareAuthorizedException",
    "ransomwareRecoveryDestruction",
    "ransomwareRecoveryDestructionBlocked",
    "ransomwareRecoveryDestructionAuthorized",
)

SAFE_FIELDS = frozenset(SAFE_NUMERIC_FIELDS + SAFE_BOOLEAN_FIELDS)
_MUTABLE_ALERT_FIELDS = frozenset(("eventCount", "blockedCount", "terminatedCount", "droppedCount"))
_ALLOWED_ALERT_KEYS = SAFE_FIELDS | {"alertId", "simulated", "simulationVerified"}
_REQUIRED_ALERT_FIELDS = ("eventType",)
_STATES = frozenset(("prepared", "acknowledged", "uncertain", "baseline"))


def _normalize_identifier(value, label="identifier"):
    if not isinstance(value, str) or len(value) > MAX_ID_LENGTH or not _ID_RE.fullmatch(value):
        raise ValueError("invalid " + label)
    return value


def _normalize_receipt(value):
    if not isinstance(value, str) or not value or len(value) > MAX_RECEIPT_LENGTH or not _RECEIPT_RE.fullmatch(value):
        raise ValueError("invalid native receipt")
    return value


def _normalize_token(value):
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ValueError("invalid notification token")
    return value


def _normalize_alert(value):
    if not isinstance(value, dict):
        raise ValueError("alert summary object required")
    unknown = set(value) - _ALLOWED_ALERT_KEYS
    if unknown:
        raise ValueError("alert contains non-allowlisted fields")
    alert_id = _normalize_identifier(value.get("alertId"), "alert ID")
    normalized = {"alertId": alert_id}
    for name in SAFE_NUMERIC_FIELDS:
        if name not in value:
            continue
        field_value = value[name]
        if type(field_value) is not int or not 0 <= field_value <= MAX_U64:
            raise ValueError("invalid numeric alert field")
        normalized[name] = field_value
    for name in SAFE_BOOLEAN_FIELDS:
        if name not in value:
            continue
        field_value = value[name]
        if type(field_value) is not bool:
            raise ValueError("invalid boolean alert field")
        normalized[name] = field_value
    for name in _REQUIRED_ALERT_FIELDS:
        if name not in normalized:
            raise ValueError("required alert field missing")
    if normalized["eventType"] > 8:
        raise ValueError("invalid event identity")
    # Simulation labels are accepted only as typed input metadata. They never
    # suppress a notification; suppression is controlled by exact IDs below.
    for name in ("simulated", "simulationVerified"):
        if name in value and type(value[name]) is not bool:
            raise ValueError("invalid simulation flag")
        if name in value:
            normalized[name] = value[name]
    return normalized


def _normalize_alerts(alert_summaries, max_inputs=MAX_INPUTS):
    if not isinstance(alert_summaries, (list, tuple)) or len(alert_summaries) > max_inputs:
        raise ValueError("alert input quota exceeded")
    normalized = {}
    for value in alert_summaries:
        item = _normalize_alert(value)
        old = normalized.get(item["alertId"])
        if old is not None and old != item:
            raise ValueError("alert ID collision")
        normalized[item["alertId"]] = item
    return normalized


def _normalize_simulation_ids(values):
    if not isinstance(values, (list, tuple, set, frozenset)) or len(values) > MAX_INPUTS:
        raise ValueError("simulation ID quota exceeded")
    return tuple(sorted({_normalize_identifier(value, "simulation ID") for value in values}))


def _normalize_fault(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"active", "code"}:
        raise ValueError("invalid source fault")
    active = value.get("active")
    if type(active) is not bool:
        raise ValueError("invalid source fault state")
    code = value.get("code")
    if code is not None and (type(code) is not int or not 0 <= code <= MAX_U32):
        raise ValueError("invalid source fault code")
    if active and code is None:
        raise ValueError("active source fault requires code")
    return {"active": active, "code": code}


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _draft_id(entry_key):
    return "d-" + hashlib.sha256(entry_key.encode("ascii")).hexdigest()


class NotificationJournal:
    """SQLite-backed prepare/ack journal with idempotent state transitions."""

    def __init__(self, db_path):
        self.path = Path(db_path)
        if not self.path.name or self.path.name in (".", ".."):
            raise ValueError("invalid notification journal path")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            # Switching a database into WAL mode takes a brief schema lock.
            # Multiple journal instances can initialize concurrently, so retry
            # that one pragma instead of leaking a handle or failing the claim.
            for attempt in range(20):
                try:
                    connection.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError:
                    if attempt == 19:
                        raise
                    time.sleep(0.01 * (attempt + 1))
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except Exception:
            connection.close()
            raise

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self):
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS batches (
                    token TEXT PRIMARY KEY,
                    canonical TEXT NOT NULL,
                    created_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS entries (
                    entry_key TEXT PRIMARY KEY,
                    token TEXT NOT NULL REFERENCES batches(token),
                    kind TEXT NOT NULL CHECK(kind IN ('alert', 'fault')),
                    alert_id TEXT,
                    payload TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('prepared', 'acknowledged', 'uncertain', 'baseline')),
                    receipt TEXT,
                    created_ns INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS entries_token_idx ON entries(token);
                CREATE TABLE IF NOT EXISTS fault_state (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    code INTEGER,
                    epoch INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS journal_meta (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    baseline_token TEXT NOT NULL
                );
                """
            )
            fault_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(fault_state)")
            }
            if "epoch" not in fault_columns:
                connection.execute(
                    "ALTER TABLE fault_state ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0"
                )

    @staticmethod
    def _entry_payload(value):
        return _canonical_json(value)

    @staticmethod
    def _same_alert_identity(old_payload_text, new_payload_text):
        old_payload = json.loads(old_payload_text)
        new_payload = json.loads(new_payload_text)
        old_identity = {
            key: value for key, value in old_payload.items() if key not in _MUTABLE_ALERT_FIELDS
        }
        new_identity = {
            key: value for key, value in new_payload.items() if key not in _MUTABLE_ALERT_FIELDS
        }
        return old_identity == new_identity

    @staticmethod
    def _token_alerts(alerts):
        return [
            {key: value for key, value in alerts[key].items() if key not in _MUTABLE_ALERT_FIELDS}
            for key in sorted(alerts)
        ]

    @staticmethod
    def _insert_entry(connection, token, entry_key, kind, alert_id, payload, state="prepared"):
        payload_text = NotificationJournal._entry_payload(payload)
        existing = connection.execute(
            "SELECT kind, alert_id, payload FROM entries WHERE entry_key=?", (entry_key,)
        ).fetchone()
        if existing is not None:
            if existing != (kind, alert_id, payload_text):
                if kind == "alert" and existing[0] == "alert" and NotificationJournal._same_alert_identity(existing[2], payload_text):
                    return False
                raise ValueError("journal identity collision")
            return False
        if connection.execute("SELECT COUNT(*) FROM entries").fetchone()[0] >= MAX_ENTRIES:
            raise RuntimeError("notification journal quota reached")
        connection.execute(
            "INSERT INTO entries(entry_key, token, kind, alert_id, payload, state, receipt, created_ns) "
            "VALUES(?,?,?,?,?,?,NULL,?)",
            (entry_key, token, kind, alert_id, payload_text, state, time.time_ns()),
        )
        return True

    @staticmethod
    def _fault_transition(connection, token, fault, previous, epoch):
        if fault is None:
            return False
        previous_active = bool(previous[0]) if previous is not None else False
        previous_code = previous[1] if previous is not None else None
        active = fault["active"]
        code = fault["code"]
        if active:
            if previous_active and previous_code == code:
                return False
            entry_key = "fault-active-" + str(code) + "-" + str(epoch)
            changed = NotificationJournal._insert_entry(
                connection, token, entry_key, "fault", None, {"active": True, "code": code}
            )
            connection.execute(
                "INSERT INTO fault_state(id, active, code, epoch) VALUES(1,1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET active=excluded.active, code=excluded.code, epoch=excluded.epoch",
                (code, epoch),
            )
            return changed
        if previous_active:
            entry_key = "fault-recovered-" + str(previous_code) + "-" + str(epoch)
            changed = NotificationJournal._insert_entry(
                connection,
                token,
                entry_key,
                "fault",
                None,
                {"active": False, "code": previous_code},
            )
            connection.execute("UPDATE fault_state SET active=0 WHERE id=1")
            return changed
        if previous is None:
            connection.execute("INSERT INTO fault_state(id, active, code, epoch) VALUES(1,0,NULL,0)")
        return False

    @staticmethod
    def _make_token(alerts, simulations, fault, fault_epoch=None, mode="prepare"):
        canonical = _canonical_json({
            "mode": mode,
            "alerts": NotificationJournal._token_alerts(alerts),
            "knownSimulationIds": list(simulations),
            "sourceFault": fault,
            "faultEpoch": fault_epoch if fault is not None else None,
        })
        return "n-" + hashlib.sha256(canonical.encode("ascii")).hexdigest(), canonical

    def prepare(self, alert_summaries, known_simulation_ids, source_fault=None):
        # None means that this page carries no fault observation. Healthy is an
        # explicit {"active": False} transition, so page polling cannot clear
        # an active fault merely because a page omitted the fault field.
        input_count = len(alert_summaries) if isinstance(alert_summaries, (list, tuple)) else None
        alerts = _normalize_alerts(alert_summaries)
        simulations = _normalize_simulation_ids(known_simulation_ids)
        fault = _normalize_fault(source_fault)
        skipped = 0
        new_keys = []
        simulation_set = set(simulations)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous_fault = connection.execute(
                    "SELECT active, code, epoch FROM fault_state WHERE id=1"
                ).fetchone()
                fault_epoch = None
                if fault is not None:
                    prior_epoch = previous_fault[2] if previous_fault is not None else 0
                    prior_active = bool(previous_fault[0]) if previous_fault is not None else False
                    prior_code = previous_fault[1] if previous_fault is not None else None
                    fault_epoch = prior_epoch + 1 if fault["active"] and (
                        not prior_active or prior_code != fault["code"]
                    ) else prior_epoch
                token, canonical = self._make_token(alerts, simulations, fault, fault_epoch)
                existing_batch = connection.execute(
                    "SELECT canonical FROM batches WHERE token=?", (token,)
                ).fetchone()
                if existing_batch is not None and existing_batch[0] != canonical:
                    raise ValueError("notification token collision")
                connection.execute(
                    "INSERT OR IGNORE INTO batches(token, canonical, created_ns) VALUES(?,?,?)",
                    (token, canonical, time.time_ns()),
                )
                for alert_id in sorted(alerts):
                    if alert_id in simulation_set:
                        skipped += 1
                        continue
                    item = alerts[alert_id]
                    entry_key = "alert:" + alert_id
                    payload = {key: value for key, value in item.items() if key != "alertId"}
                    if self._insert_entry(connection, token, entry_key, "alert", alert_id, payload):
                        new_keys.append(entry_key)
                if fault is not None:
                    before = connection.execute(
                        "SELECT entry_key FROM entries WHERE token=? AND kind='fault'", (token,)
                    ).fetchall()
                    self._fault_transition(connection, token, fault, previous_fault, fault_epoch)
                    after = connection.execute(
                        "SELECT entry_key FROM entries WHERE token=? AND kind='fault'", (token,)
                    ).fetchall()
                    old_keys = {row[0] for row in before}
                    new_keys.extend(row[0] for row in after if row[0] not in old_keys)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        drafts = self._drafts_for_keys(token, new_keys)
        return {
            "schema": "KProNotificationPrepare/v1",
            "token": token,
            "drafts": drafts,
            "inputCount": input_count,
            "newDraftCount": len(drafts),
            "skippedSimulationCount": skipped,
            "delivered": False,
        }

    def baseline(self, alert_summaries, known_simulation_ids):
        """Initialize historical state without manufacturing delivery receipts."""
        input_count = len(alert_summaries) if isinstance(alert_summaries, (list, tuple)) else None
        alerts = _normalize_alerts(alert_summaries, max_inputs=MAX_BASELINE_INPUTS)
        simulations = _normalize_simulation_ids(known_simulation_ids)
        token, canonical = self._make_token(alerts, simulations, None, mode="baseline")
        skipped = 0
        baseline_count = 0
        simulation_set = set(simulations)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if connection.execute("SELECT 1 FROM journal_meta WHERE id=1").fetchone() is not None:
                    raise ValueError("notification baseline already initialized")
                if connection.execute("SELECT 1 FROM entries LIMIT 1").fetchone() is not None:
                    raise ValueError("notification baseline requires an empty journal")
                connection.execute(
                    "INSERT INTO batches(token, canonical, created_ns) VALUES(?,?,?)",
                    (token, canonical, time.time_ns()),
                )
                for alert_id in sorted(alerts):
                    if alert_id in simulation_set:
                        skipped += 1
                        continue
                    item = alerts[alert_id]
                    payload = {key: value for key, value in item.items() if key != "alertId"}
                    if self._insert_entry(
                        connection, token, "alert:" + alert_id, "alert", alert_id, payload, state="baseline"
                    ):
                        baseline_count += 1
                connection.execute(
                    "INSERT INTO journal_meta(id, baseline_token) VALUES(1,?)", (token,)
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return {
            "schema": "KProNotificationBaseline/v1",
            "token": token,
            "drafts": [],
            "inputCount": input_count,
            "baselineCount": baseline_count,
            "skippedSimulationCount": skipped,
            "initialized": True,
            "delivered": False,
        }

    def _draft_from_row(self, row):
        entry_key, kind, alert_id, payload_text, state, receipt = row
        payload = json.loads(payload_text)
        draft = {
            "draftId": _draft_id(entry_key),
            "kind": kind,
            "fields": payload,
            "state": state,
            "delivered": state == "acknowledged",
        }
        if alert_id is not None:
            draft["alertId"] = alert_id
        if receipt is not None:
            draft["nativeReceipt"] = receipt
        return draft

    def _drafts_for_keys(self, token, entry_keys):
        if not entry_keys:
            return []
        with self._connection() as connection:
            rows = []
            for entry_key in sorted(set(entry_keys)):
                row = connection.execute(
                    "SELECT entry_key, kind, alert_id, payload, state, receipt "
                    "FROM entries WHERE token=? AND entry_key=?",
                    (token, entry_key),
                ).fetchone()
                if row is not None:
                    rows.append(row)
            return [self._draft_from_row(row) for row in rows]

    def ack(self, token, native_receipt):
        token = _normalize_token(token)
        receipt = _normalize_receipt(native_receipt)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if connection.execute("SELECT 1 FROM batches WHERE token=?", (token,)).fetchone() is None:
                    raise ValueError("unknown notification token")
                receipt_owner = connection.execute(
                    "SELECT token FROM entries WHERE receipt=? AND token<>? LIMIT 1",
                    (receipt, token),
                ).fetchone()
                if receipt_owner is not None:
                    raise ValueError("native receipt is bound to another token")
                rows = connection.execute(
                    "SELECT entry_key, state, receipt FROM entries WHERE token=?", (token,)
                ).fetchall()
                if any(state == "baseline" for _, state, _ in rows):
                    raise ValueError("baseline entries cannot be acknowledged")
                changed = 0
                for entry_key, state, old_receipt in rows:
                    if state == "acknowledged":
                        if old_receipt != receipt:
                            raise ValueError("receipt does not match token binding")
                        continue
                    connection.execute(
                        "UPDATE entries SET state='acknowledged', receipt=? WHERE entry_key=?",
                        (receipt, entry_key),
                    )
                    changed += 1
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        result = self.status(token)
        result.update({"acknowledgedCount": changed, "nativeReceipt": receipt})
        return result

    def mark_uncertain(self, token):
        token = _normalize_token(token)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if connection.execute("SELECT 1 FROM batches WHERE token=?", (token,)).fetchone() is None:
                    raise ValueError("unknown notification token")
                if connection.execute(
                    "SELECT 1 FROM entries WHERE token=? AND state='baseline'", (token,)
                ).fetchone() is not None:
                    raise ValueError("baseline entries cannot become uncertain")
                connection.execute(
                    "UPDATE entries SET state='uncertain' WHERE token=? AND state='prepared'", (token,)
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        result = self.status(token)
        return result

    def status(self, token=None, after_token=None):
        if token is not None:
            token = _normalize_token(token)
        if after_token is not None:
            after_token = _normalize_token(after_token)
            if token is not None:
                raise ValueError('token and pending cursor cannot be combined')
        with self._connection() as connection:
            fault_row = connection.execute(
                "SELECT active, code, epoch FROM fault_state WHERE id=1"
            ).fetchone()
            fault_state = {
                "active": bool(fault_row[0]) if fault_row is not None else False,
                "code": fault_row[1] if fault_row is not None else None,
                "epoch": fault_row[2] if fault_row is not None else 0,
            }
            initialized = connection.execute(
                "SELECT 1 FROM journal_meta WHERE id=1"
            ).fetchone() is not None
            if token is not None and connection.execute(
                "SELECT 1 FROM batches WHERE token=?", (token,)
            ).fetchone() is None:
                raise ValueError("unknown notification token")
            if token is None:
                counts = dict(connection.execute(
                    "SELECT state, COUNT(*) FROM entries GROUP BY state"
                ).fetchall())
                entry_count = connection.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
                batch_count = connection.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
                pending = [row[0] for row in connection.execute(
                    "SELECT DISTINCT token FROM entries WHERE state IN ('prepared','uncertain') "
                    "AND token>? ORDER BY token LIMIT 21", (after_token or '',)
                ).fetchall()]
                return {
                    "schema": "KProNotificationStatus/v1",
                    "batchCount": batch_count,
                    "entryCount": entry_count,
                    "stateCounts": {state: counts.get(state, 0) for state in sorted(_STATES)},
                    "initialized": initialized,
                    "faultState": fault_state,
                    "pendingTokens": pending[:20],
                    "pendingHasMore": len(pending)>20,
                    "nextPendingCursor": pending[19] if len(pending)>20 else None,
                }
            rows = connection.execute(
                "SELECT entry_key, kind, alert_id, payload, state, receipt "
                "FROM entries WHERE token=? ORDER BY entry_key",
                (token,),
            ).fetchall()
            counts = {}
            for row in rows:
                counts[row[4]] = counts.get(row[4], 0) + 1
            return {
                "schema": "KProNotificationStatus/v1",
                "token": token,
                "entryCount": len(rows),
                "stateCounts": {state: counts.get(state, 0) for state in sorted(_STATES) if counts.get(state, 0)},
                "initialized": initialized,
                "delivered": bool(rows) and all(row[4] == "acknowledged" for row in rows),
                "faultState": fault_state,
                "entries": [self._draft_from_row(row) for row in rows],
            }

    # The short alias is convenient for adapters while preserving one explicit
    # method name in the public contract.
    uncertain = mark_uncertain
