"""按订单站点验收的镜像交付履约台账。

边缘节点的发送字节数（``edge_transfer`` / ``provisional_bytes``）、环境摘要指针
（``channel``）和工作负载租约（``admission``）都不能证明完整镜像已经抵达客户的
某个机房。本模块只把以下事实当作验收依据，并让它们共同复算出履约结论：

1. 订单承诺：镜像摘要、客户账号、固定的客户站点、交付时窗/宽限期、完整分片范围、
   按日减免标准；
2. 分片事实：每个分片的内容摘要与字节数；
3. 客户站点回执：绑定 ``(订单, 站点)`` 的分片内容回执与整镜像摘要回执；
4. 补交方式：网络补片或预装同摘要的加密缓存设备（封签、客户独占解密权、承运/仓库
   交接证据、运费）；
5. 供应商带宽收费原件与支付状态；
6. 不可变的签收/交付时间，以及签收后漏片引发的违约补交、更正与减免台账。

设计约定与 ``imagecourt`` 其它子系统一致：只使用标准库 + SQLite，``run(db, x)``
按 ``op`` 分派并返回带 ``decision`` 的字典；所有结论都能从表内事实重新计算。
"""

from __future__ import annotations

import functools
import hashlib
import json
import sqlite3
import weakref

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS cf_orders(
  order_id TEXT PRIMARY KEY,
  account TEXT NOT NULL,
  digest TEXT NOT NULL,
  window_start INTEGER,
  window_end INTEGER,
  grace_end INTEGER,
  day_seconds INTEGER NOT NULL DEFAULT 86400,
  daily_credit NUMERIC NOT NULL DEFAULT 0,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER,
  commitment TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cf_order_sites(
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(order_id, site)
);
CREATE TABLE IF NOT EXISTS cf_chunks(
  order_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  chunk_digest TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(order_id, idx)
);
CREATE TABLE IF NOT EXISTS cf_edge_sends(
  event_id TEXT PRIMARY KEY,
  order_id TEXT,
  digest TEXT,
  account TEXT,
  site TEXT,
  node_id TEXT,
  chunk_idx INTEGER,
  bytes_sent INTEGER NOT NULL DEFAULT 0,
  at INTEGER,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS cf_receipts(
  receipt_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  idx INTEGER NOT NULL,
  chunk_digest TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  at INTEGER,
  via TEXT NOT NULL DEFAULT 'customer',
  status TEXT NOT NULL,
  payload TEXT
);
CREATE INDEX IF NOT EXISTS cf_receipts_logical
  ON cf_receipts(order_id, site, idx, status);
CREATE TABLE IF NOT EXISTS cf_digest_acks(
  ack_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  digest TEXT,
  at INTEGER,
  via TEXT NOT NULL DEFAULT 'customer',
  status TEXT NOT NULL,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS cf_acceptances(
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  accepted_at INTEGER,
  delivered_at INTEGER NOT NULL,
  notified_at INTEGER,
  digest TEXT,
  remediation_id TEXT,
  joint_id TEXT,
  basis TEXT,
  PRIMARY KEY(order_id, site)
);
CREATE TABLE IF NOT EXISTS cf_joint_acceptances(
  joint_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  device_id TEXT,
  at INTEGER,
  sites TEXT NOT NULL,
  remediation_id TEXT
);
CREATE TABLE IF NOT EXISTS cf_portal_marks(
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  marked_accepted INTEGER NOT NULL,
  at INTEGER,
  source TEXT,
  PRIMARY KEY(order_id, site)
);
CREATE TABLE IF NOT EXISTS cf_remediations(
  remediation_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  method TEXT NOT NULL,
  opened_at INTEGER,
  closed_at INTEGER,
  status TEXT NOT NULL,
  device_id TEXT,
  note TEXT
);
CREATE TABLE IF NOT EXISTS cf_devices(
  device_id TEXT PRIMARY KEY,
  order_id TEXT,
  digest TEXT,
  decryption_rights TEXT NOT NULL DEFAULT 'customer_only',
  key_holder TEXT,
  seal_status TEXT NOT NULL DEFAULT 'intact',
  status TEXT NOT NULL DEFAULT 'registered',
  issued_at INTEGER,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS cf_seal_events(
  seal_event_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  seal_id TEXT,
  status TEXT NOT NULL,
  at INTEGER,
  note TEXT
);
CREATE TABLE IF NOT EXISTS cf_custody(
  checkpoint_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  at INTEGER,
  party TEXT,
  kind TEXT,
  code TEXT,
  seal_id TEXT,
  seal_intact INTEGER,
  customer_key_only INTEGER,
  proof_ref TEXT,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS cf_shipments(
  shipment_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  order_id TEXT,
  site TEXT,
  direction TEXT NOT NULL DEFAULT 'outbound',
  carrier TEXT,
  at INTEGER,
  cost NUMERIC NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'CNY',
  billed_to TEXT NOT NULL DEFAULT 'platform',
  via TEXT,
  status TEXT NOT NULL DEFAULT 'shipped'
);
CREATE TABLE IF NOT EXISTS cf_device_verifications(
  verification_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  at INTEGER,
  outcome TEXT NOT NULL,
  reason TEXT,
  verified_indexes TEXT
);
CREATE TABLE IF NOT EXISTS cf_handoffs(
  node_id TEXT PRIMARY KEY,
  current_name TEXT
);
CREATE TABLE IF NOT EXISTS cf_handoff_aliases(
  node_id TEXT NOT NULL,
  name TEXT NOT NULL,
  at INTEGER,
  PRIMARY KEY(node_id, name)
);
CREATE TABLE IF NOT EXISTS cf_vendor_charges(
  charge_id TEXT PRIMARY KEY,
  vendor TEXT,
  node_id TEXT,
  handoff_name TEXT,
  digest TEXT,
  order_id TEXT,
  amount NUMERIC NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY',
  period_start INTEGER,
  period_end INTEGER,
  at INTEGER,
  status TEXT NOT NULL DEFAULT 'recorded',
  paid_at INTEGER,
  original_payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cf_corrections(
  correction_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  at INTEGER,
  kind TEXT NOT NULL,
  missing_indexes TEXT,
  invalidate_receipt_id TEXT,
  original_delivered_at INTEGER,
  original_accepted_at INTEGER,
  note TEXT
);
CREATE TABLE IF NOT EXISTS cf_credit_grants(
  grant_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  site TEXT NOT NULL,
  amount NUMERIC NOT NULL,
  at INTEGER,
  reason TEXT,
  remediation_id TEXT,
  correction_id TEXT,
  calc TEXT
);
"""

_READY_CONNS = weakref.WeakSet()


def ensure_schema(db):
    """Create fulfillment tables. Safe to call repeatedly and inside a tx.

    Statements are executed individually (not ``executescript``) so an open
    ``BEGIN IMMEDIATE`` transaction is never implicitly committed.
    """
    try:
        if db in _READY_CONNS:
            return db
    except TypeError:
        pass
    try:
        if db.row_factory is None:
            db.row_factory = sqlite3.Row
    except Exception:
        pass
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cf_orders'"
    ).fetchone()
    if not exists:
        for statement in SCHEMA.split(";"):
            statement = statement.strip()
            if statement:
                db.execute(statement)
    try:
        _READY_CONNS.add(db)
    except TypeError:
        pass
    return db


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _one(db, sql, args=()):
    row = db.execute(sql, args).fetchone()
    return dict(row) if row is not None else None


def _all(db, sql, args=()):
    return [dict(r) for r in db.execute(sql, args).fetchall()]


def _merge(payload, kwargs, str_key=None):
    p = {}
    if payload is not None:
        if isinstance(payload, dict):
            p.update(payload)
        elif str_key is not None:
            p[str_key] = payload
        else:
            raise TypeError("payload must be a dict")
    p.update(kwargs)
    return p


_ALIASES = {
    "order_id": ("order", "order_ref", "oid", "order_no"),
    "site": ("site_id", "site_code", "dc", "datacenter", "site_name"),
    "account": ("customer", "account_id", "customer_id", "tenant", "account_no"),
    "digest": ("image_digest", "manifest_digest", "promised_digest", "sha"),
    "at": ("time", "occurred_at", "timestamp", "when", "on", "event_at"),
    "chunk_idx": ("idx", "chunk", "chunk_index", "index", "seq", "position"),
    "receipt_id": ("id", "receipt_ref"),
    "ack_id": ("id", "ack_ref"),
    "event_id": ("id", "edge_event_id", "transfer_id"),
    "remediation_id": ("id", "remedy_id", "cure_id", "case_id"),
    "device_id": ("device", "cache_device_id"),
    "shipment_id": ("id", "ship_ref"),
    "verification_id": ("id", "verify_id"),
    "checkpoint_id": ("id", "checkpoint_ref"),
    "charge_id": ("id", "vendor_charge_id"),
    "correction_id": ("id",),
    "grant_id": ("id", "credit_id"),
    "joint_id": ("id",),
    "seal_event_id": ("id",),
    "window_start": ("start", "window_begin", "start_at"),
    "window_end": ("end", "window_until", "end_at", "deadline"),
    "grace_end": ("grace_until", "grace_deadline", "grace_period_end"),
    "day_seconds": ("seconds_per_day", "time_unit_seconds"),
    "daily_credit": ("credit_per_day", "daily_relief", "relief_per_day", "daily_amount"),
    "chunks": ("content", "content_scope", "scope", "parts"),
    "sites": ("site_list", "customer_sites"),
    "total_bytes": ("bytes_total", "content_bytes", "size_bytes"),
    "chunk_digest": ("part_digest", "content_hash", "chunk_hash"),
    "bytes_sent": ("sent_bytes", "bytes", "byte_count"),
    "node_id": ("node", "edge_node", "handoff_id", "pop"),
    "method": ("remediation_method", "cure_method", "kind_method"),
    "cost": ("shipping_cost", "fee", "amount_shipping"),
    "paid_at": ("payment_at", "paid_time"),
    "amount": ("charge_amount", "total", "value"),
}


def _norm(p, *canonical_keys):
    """Apply field aliases in-place and return p."""
    for canon in canonical_keys:
        if p.get(canon) is None:
            for alias in _ALIASES.get(canon, ()):  # type: ignore[arg-type]
                if p.get(alias) is not None:
                    p[canon] = p[alias]
                    break
    return p


def _dictable(fn):
    """Allow ``fn(db, {...payload...})`` in addition to keyword calls."""

    @functools.wraps(fn)
    def wrapper(db, *args, **kwargs):
        ensure_schema(db)
        if len(args) == 1 and isinstance(args[0], dict):
            data = dict(args[0])
            data.update(kwargs)
            return fn(db, **data)
        return fn(db, *args, **kwargs)

    return wrapper


def _same(existing, expected_fields):
    for k, v in expected_fields.items():
        if existing.get(k) != v:
            return False
    return True


# ---------------------------------------------------------------------------
# 1. Order commitments
# ---------------------------------------------------------------------------

@_dictable
def commit_order(db, payload=None, **kwargs):
    """固定订单承诺。

    必需：``order_id, account, digest, sites, window_start, window_end, chunks``。
    ``chunks`` 可以是分片数量（int）、分片索引列表，或
    ``[{"idx":0,"digest":"sha256:...","bytes":100}, ...]``。
    """
    p = _norm(_merge(payload, kwargs),
              "order_id", "account", "digest", "sites", "window_start",
              "window_end", "grace_end", "day_seconds", "daily_credit",
              "chunks", "total_bytes", "at")
    oid = p.get("order_id")
    if not oid:
        return {"decision": "invalid_payload", "reason": "order_id_required"}
    sites = p.get("sites")
    single_site = p.get("site")
    if sites is None and single_site is not None:
        sites = [single_site]
    if isinstance(sites, str):
        sites = [s.strip() for s in sites.split(",") if s.strip()]
    if not sites:
        return {"decision": "sites_required"}
    if p.get("window_start") is None or p.get("window_end") is None:
        return {"decision": "invalid_window", "reason": "window_required"}
    if p["window_start"] >= p["window_end"]:
        return {"decision": "invalid_window"}
    grace_end = p.get("grace_end")
    if grace_end is not None and grace_end < p["window_end"]:
        return {"decision": "invalid_grace_period"}

    chunk_specs = _normalize_chunks(p.get("chunks"))
    if not chunk_specs:
        return {"decision": "content_scope_required"}
    chunk_bytes = p.get("chunk_bytes", p.get("part_bytes", p.get("chunk_size")))
    if chunk_bytes:
        for c in chunk_specs:
            if not c["bytes"]:
                c["bytes"] = int(chunk_bytes)
    total_bytes = p.get("total_bytes")
    if total_bytes is None:
        total_bytes = sum(c["bytes"] for c in chunk_specs)

    commitment = json.dumps(
        {
            "order_id": oid,
            "account": p.get("account"),
            "digest": p.get("digest"),
            "sites": list(sites),
            "window_start": p["window_start"],
            "window_end": p["window_end"],
            "grace_end": grace_end,
            "day_seconds": p.get("day_seconds", 86400),
            "daily_credit": p.get("daily_credit", 0),
            "total_bytes": total_bytes,
            "chunks": chunk_specs,
        },
        sort_keys=True,
        ensure_ascii=False,
    )

    old = _one(db, "SELECT * FROM cf_orders WHERE order_id=?", (oid,))
    if old:
        if old["commitment"] == commitment:
            return {"decision": "reused", "order_id": oid}
        return {"decision": "order_identity_conflict", "order_id": oid}

    db.execute(
        "INSERT INTO cf_orders(order_id,account,digest,window_start,window_end,"
        "grace_end,day_seconds,daily_credit,total_bytes,created_at,commitment) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (oid, p.get("account"), p.get("digest"), p["window_start"],
         p["window_end"], grace_end, p.get("day_seconds", 86400),
         p.get("daily_credit", 0), total_bytes, p.get("at"), commitment),
    )
    for seq, site in enumerate(sites):
        db.execute("INSERT OR IGNORE INTO cf_order_sites(order_id,site,seq) VALUES(?,?,?)",
                   (oid, str(site), seq))
    for c in chunk_specs:
        db.execute("INSERT INTO cf_chunks(order_id,idx,chunk_digest,bytes) VALUES(?,?,?,?)",
                   (oid, c["idx"], c.get("digest"), c["bytes"]))
    return {"decision": "order_committed", "order_id": oid,
            "sites": list(sites), "chunks": len(chunk_specs),
            "total_bytes": total_bytes}


create_order = commit_order
register_order = commit_order


def _normalize_chunks(chunks):
    if chunks is None:
        return []
    if isinstance(chunks, int):
        return [{"idx": i, "digest": None, "bytes": 0} for i in range(chunks)]
    out = []
    if isinstance(chunks, (list, tuple)):
        for i, c in enumerate(chunks):
            if isinstance(c, int):
                # bare integer in list is an index
                out.append({"idx": c, "digest": None, "bytes": 0})
            elif isinstance(c, dict):
                idx = c.get("idx", c.get("index", c.get("chunk_index", i)))
                digest = c.get("digest", c.get("chunk_digest", c.get("hash")))
                size = c.get("bytes", c.get("size", c.get("byte_count", 0))) or 0
                out.append({"idx": int(idx), "digest": digest, "bytes": int(size)})
    # fill default equal sizes if a chunk_size hint encoded elsewhere is unavailable
    return out


def _load_order(db, order_id):
    if not order_id:
        return None
    return _one(db, "SELECT * FROM cf_orders WHERE order_id=?", (order_id,))


def _order_sites(db, order_id):
    return [r["site"] for r in _all(
        db, "SELECT site FROM cf_order_sites WHERE order_id=? ORDER BY seq,site",
        (order_id,))]


def _chunk_specs(db, order_id):
    return _all(db, "SELECT idx,chunk_digest,bytes FROM cf_chunks WHERE order_id=? ORDER BY idx",
                 (order_id,))


# ---------------------------------------------------------------------------
# 2. Untrusted edge send records (retry duplicates kept as originals)
# ---------------------------------------------------------------------------

@_dictable
def record_edge_send(db, payload=None, **kwargs):
    """登记边缘节点自称已发送的事实。明确不是客户收件证明。"""
    p = _norm(_merge(payload, kwargs), "event_id", "order_id", "digest",
              "account", "site", "node_id", "chunk_idx", "bytes_sent", "at")
    eid = p.get("event_id")
    if not eid:
        return {"decision": "invalid_payload", "reason": "event_id_required"}
    old = _one(db, "SELECT * FROM cf_edge_sends WHERE event_id=?", (eid,))
    fields = {
        "order_id": p.get("order_id"), "digest": p.get("digest"),
        "account": p.get("account"), "site": p.get("site"),
        "node_id": p.get("node_id"), "chunk_idx": p.get("chunk_idx"),
        "bytes_sent": p.get("bytes_sent", 0) or 0, "at": p.get("at"),
    }
    if old:
        if _same(old, fields):
            return {"decision": "reused", "event_id": eid}
        return {"decision": "edge_event_conflict", "event_id": eid}
    db.execute(
        "INSERT INTO cf_edge_sends(event_id,order_id,digest,account,site,node_id,"
        "chunk_idx,bytes_sent,at,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (eid, fields["order_id"], fields["digest"], fields["account"],
         fields["site"], fields["node_id"], fields["chunk_idx"],
         fields["bytes_sent"], fields["at"],
         json.dumps(payload if isinstance(payload, dict) else p, sort_keys=True,
                    ensure_ascii=False, default=str)),
    )
    # Also feed the legacy provisional tally table when its schema is present or
    # when the caller asks for the shared tally. This keeps the naive trap visible.
    try:
        db.execute(
            "CREATE TABLE IF NOT EXISTS edge_transfers(event TEXT PRIMARY KEY,"
            "digest TEXT,customer TEXT,bytes_sent INTEGER)"
        )
        db.execute("INSERT OR IGNORE INTO edge_transfers VALUES(?,?,?,?)",
                   (eid, fields["digest"], fields["account"], fields["bytes_sent"]))
    except sqlite3.Error:
        pass
    return {"decision": "edge_send_recorded", "event_id": eid, "proof": False}


edge_send = record_edge_send
record_send = record_edge_send
report_edge_send = record_edge_send


def naive_account_bytes(db, digest, account):
    """复刻 customer_delivery.provisional_bytes 的直接求和（仅作对照，不可验收）。"""
    try:
        return db.execute(
            "SELECT COALESCE(SUM(bytes_sent),0) FROM edge_transfers "
            "WHERE digest=? AND customer=?", (digest, account)
        ).fetchone()[0]
    except sqlite3.Error:
        return _one(
            db,
            "SELECT COALESCE(SUM(bytes_sent),0) AS n FROM cf_edge_sends "
            "WHERE digest=? AND account=?",
            (digest, account),
        )["n"]


@_dictable
def lose_edge_cache(db, payload=None, **kwargs):
    """模拟边缘缓存丢失：删除边缘自称的发送记录。

    客户回执与签收事实不受影响——验收从来不建立在边缘计数上，因此边缘缓存
    丢失既不能取消已验收站点，也不能把一个站点的收件改记到另一个站点。
    """
    p = _norm(_merge(payload, kwargs), "order_id", "digest", "account")
    oid = p.get("order_id")
    order = _load_order(db, oid) if oid else None
    digest = p.get("digest") or (order["digest"] if order else None)
    account = p.get("account") or (order["account"] if order else None)
    cur = db.execute(
        "DELETE FROM cf_edge_sends WHERE order_id=? OR digest=? OR account=?",
        (oid, digest, account))
    removed = cur.rowcount
    try:
        db.execute("DELETE FROM edge_transfers WHERE digest=? OR customer=?",
                   (digest, account))
    except sqlite3.Error:
        pass
    return {"decision": "edge_cache_lost", "removed_edge_records": removed,
            "customer_proof_retained": True}


# ---------------------------------------------------------------------------
# 3. Customer site-bound receipts
# ---------------------------------------------------------------------------

@_dictable
def record_chunk_receipt(db, payload=None, **kwargs):
    """客户侧分片内容回执。

    回执必须绑定订单与具体站点；同一逻辑分片 ``(order, site, idx, digest)`` 的
    重试/重复上报只计一次。分片摘要与订单承诺不符时保留证据但不计入完整内容。
    """
    p = _norm(_merge(payload, kwargs), "receipt_id", "order_id", "site",
              "chunk_idx", "chunk_digest", "at", "via", "bytes")
    rid = p.get("receipt_id")
    oid, site = p.get("order_id"), p.get("site")
    idx = p.get("chunk_idx")
    if not rid:
        return {"decision": "invalid_payload", "reason": "receipt_id_required"}
    if idx is None:
        return {"decision": "invalid_payload", "reason": "chunk_index_required"}
    idx = int(idx)

    old = _one(db, "SELECT * FROM cf_receipts WHERE receipt_id=?", (rid,))
    if old:
        return {"decision": "reused" if (old["order_id"], old["site"], old["idx"])
                == (oid, site, idx) else "receipt_identity_conflict",
                "receipt_id": rid}

    order = _load_order(db, oid)
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    if site not in _order_sites(db, oid):
        return {"decision": "site_not_on_order", "order_id": oid, "site": site}
    spec = _one(db, "SELECT * FROM cf_chunks WHERE order_id=? AND idx=?", (oid, idx))
    if not spec:
        db.execute(
            "INSERT INTO cf_receipts(receipt_id,order_id,site,idx,chunk_digest,bytes,"
            "at,via,status,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, oid, site, idx, p.get("chunk_digest"), p.get("bytes", 0) or 0,
             p.get("at"), p.get("via", "customer"), "out_of_scope",
             json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
        return {"decision": "chunk_out_of_scope", "order_id": oid,
                "site": site, "chunk_idx": idx}

    given_digest = p.get("chunk_digest")
    expected_digest = spec["chunk_digest"]
    size = p.get("bytes") or spec["bytes"] or 0
    if expected_digest and given_digest and given_digest != expected_digest:
        db.execute(
            "INSERT INTO cf_receipts(receipt_id,order_id,site,idx,chunk_digest,bytes,"
            "at,via,status,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, oid, site, idx, given_digest, size, p.get("at"),
             p.get("via", "customer"), "mismatch",
             json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
        return {"decision": "chunk_digest_mismatch", "order_id": oid,
                "site": site, "chunk_idx": idx,
                "expected": expected_digest, "received": given_digest}

    logical = _one(
        db,
        "SELECT receipt_id FROM cf_receipts WHERE order_id=? AND site=? AND idx=? "
        "AND status='verified' LIMIT 1",
        (oid, site, idx))
    if logical:
        db.execute(
            "INSERT INTO cf_receipts(receipt_id,order_id,site,idx,chunk_digest,bytes,"
            "at,via,status,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, oid, site, idx, given_digest or expected_digest, size,
             p.get("at"), p.get("via", "customer"), "repeated",
             json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
        return {"decision": "chunk_receipt_deduplicated", "order_id": oid,
                "site": site, "chunk_idx": idx, "counted": False,
                "original_receipt_id": logical["receipt_id"]}

    db.execute(
        "INSERT INTO cf_receipts(receipt_id,order_id,site,idx,chunk_digest,bytes,"
        "at,via,status,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (rid, oid, site, idx, given_digest or expected_digest, size,
         p.get("at"), p.get("via", "customer"), "verified",
         json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
    return {"decision": "chunk_receipt_recorded", "order_id": oid,
            "site": site, "chunk_idx": idx, "counted": True}


receive_chunk = record_chunk_receipt
chunk_receipt = record_chunk_receipt
add_receipt = record_chunk_receipt


@_dictable
def record_digest_ack(db, payload=None, **kwargs):
    """客户对站点处整镜像摘要的核验回执。摘要必须等于订单承诺。"""
    p = _norm(_merge(payload, kwargs), "ack_id", "order_id", "site",
              "digest", "at", "via")
    aid = p.get("ack_id")
    oid, site = p.get("order_id"), p.get("site")
    if not aid:
        return {"decision": "invalid_payload", "reason": "ack_id_required"}
    old = _one(db, "SELECT * FROM cf_digest_acks WHERE ack_id=?", (aid,))
    if old:
        return {"decision": "reused", "ack_id": aid}
    order = _load_order(db, oid)
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    if site not in _order_sites(db, oid):
        return {"decision": "site_not_on_order", "site": site}
    status = "verified" if p.get("digest") == order["digest"] else "mismatch"
    db.execute(
        "INSERT INTO cf_digest_acks(ack_id,order_id,site,digest,at,via,status,payload) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (aid, oid, site, p.get("digest"), p.get("at"),
         p.get("via", "customer"), status,
         json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
    if status == "mismatch":
        return {"decision": "digest_mismatch", "order_id": oid, "site": site,
                "promised": order["digest"], "acknowledged": p.get("digest")}
    return {"decision": "digest_ack_recorded", "order_id": oid, "site": site}


ack_digest = record_digest_ack
digest_ack = record_digest_ack
acknowledge_digest = record_digest_ack


# ---------------------------------------------------------------------------
# 4. Portal marks are claims, never proof
# ---------------------------------------------------------------------------

@_dictable
def mark_portal_accepted(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "order_id", "site", "at", "source")
    oid, site = p.get("order_id"), p.get("site")
    if not _load_order(db, oid):
        return {"decision": "unknown_order", "order_id": oid}
    db.execute(
        "INSERT INTO cf_portal_marks(order_id,site,marked_accepted,at,source) "
        "VALUES(?,?,?,?,?) ON CONFLICT(order_id,site) DO UPDATE SET "
        "marked_accepted=excluded.marked_accepted,at=excluded.at,source=excluded.source",
        (oid, site, 1 if p.get("accepted", True) else 0, p.get("at"),
         p.get("source", "portal")))
    return {"decision": "portal_mark_recorded", "order_id": oid, "site": site,
            "proof": False}


portal_mark = mark_portal_accepted


# ---------------------------------------------------------------------------
# 5. Proof evaluation + immutable acceptance
# ---------------------------------------------------------------------------

def _site_proof(db, order, site):
    """Recompute the verified content state for one order site."""
    oid = order["order_id"]
    specs = _chunk_specs(db, oid)
    verified_rows = _all(
        db,
        "SELECT rowid AS rid, * FROM cf_receipts "
        "WHERE order_id=? AND site=? AND status='verified'",
        (oid, site))
    # Earliest valid receipt per logical chunk (insertion order breaks ties),
    # so duplicate / retried receipts never multiply content.
    earliest = {}
    for r in verified_rows:
        key = (r["at"] if r["at"] is not None else 10 ** 18, r["rid"])
        cur = earliest.get(r["idx"])
        if cur is None or key < cur[0]:
            earliest[r["idx"]] = (key, r)
    receipts = {idx: v[1] for idx, v in earliest.items()}

    # Receipts invalidated by a post-signoff shortfall are flipped to
    # 'challenged' (row retained as evidence) and therefore no longer count.
    expected_idx = [c["idx"] for c in specs]
    missing = [i for i in expected_idx if i not in receipts]
    total_bytes = order["total_bytes"] or sum(c["bytes"] for c in specs)
    missing_bytes = sum(c["bytes"] for c in specs if c["idx"] in missing)
    verified_bytes = total_bytes - missing_bytes

    ack = _one(
        db,
        "SELECT * FROM cf_digest_acks WHERE order_id=? AND site=? AND status='verified' "
        "ORDER BY at IS NULL, at, rowid LIMIT 1",
        (oid, site))
    proof_times = [r["at"] for r in receipts.values() if r["at"] is not None]
    if ack and ack["at"] is not None:
        proof_times.append(ack["at"])
    proof_ready_at = max(proof_times) if proof_times else None

    complete = not missing and ack is not None and bool(specs)
    return {
        "specs": specs,
        "receipts": receipts,
        "expected_indexes": expected_idx,
        "verified_indexes": sorted(receipts),
        "missing_indexes": missing,
        "total_bytes": total_bytes,
        "missing_bytes": missing_bytes,
        "verified_bytes": verified_bytes,
        "digest_ack": ack,
        "digest_verified": ack is not None,
        "proof_ready_at": proof_ready_at,
        "complete": complete,
    }


@_dictable
def calculate_site_credit(db, order_id=None, site=None, as_of=None, **kwargs):
    """按每个分片实际迟交的日数与未交状态，复算按日减免。

    credit = daily_credit * Σ(bytes_i/total_bytes * late_days_i)
    未交分片在给定 ``as_of`` 前按持续未交累计。时间为整数；``day_seconds=1``
    时时间轴本身就是“日”序号。
    """
    if as_of is None:
        as_of = kwargs.get("at")
    if order_id is None:
        order_id = kwargs.get("order") or kwargs.get("oid") or kwargs.get("id")
    if site is None:
        site = kwargs.get("site_id") or kwargs.get("dc")
    order = _load_order(db, order_id)
    if not order:
        return 0
    proof = _site_proof(db, order, site)
    day_seconds = order["day_seconds"] or 86400
    rate = order["daily_credit"] or 0
    total = proof["total_bytes"] or 1
    numerator = 0
    for spec in proof["specs"]:
        idx = spec["idx"]
        rc = proof["receipts"].get(idx)
        end_t = rc["at"] if rc is not None else as_of
        if end_t is None:
            continue
        late = end_t - order["window_end"]
        units = 0 if late <= 0 else (late + day_seconds - 1) // day_seconds
        numerator += (spec["bytes"] or 0) * units
    value = rate * numerator / total
    return int(value) if float(value).is_integer() else round(value, 6)


credit_for_site = calculate_site_credit
compute_credit = calculate_site_credit


@_dictable
def accept_site(db, payload=None, **kwargs):
    """凭客户回执验收一个订单站点。签收行不可变，重复调用不会产生第二次验收。"""
    p = _norm(_merge(payload, kwargs), "order_id", "site", "at",
              "delivered_at", "notified_at", "remediation_id", "joint_id", "grant_id")
    oid, site = p.get("order_id"), p.get("site")
    order = _load_order(db, oid)
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    if site not in _order_sites(db, oid):
        return {"decision": "site_not_on_order", "order_id": oid, "site": site}

    existing = _one(db, "SELECT * FROM cf_acceptances WHERE order_id=? AND site=?",
                    (oid, site))
    if existing:
        return {"decision": "site_already_accepted", "order_id": oid, "site": site,
                "accepted_at": existing["accepted_at"],
                "delivered_at": existing["delivered_at"]}

    proof = _site_proof(db, order, site)
    if proof["missing_indexes"]:
        return {"decision": "incomplete_content", "order_id": oid, "site": site,
                "missing_chunks": proof["missing_indexes"],
                "missing_bytes": proof["missing_bytes"]}
    if not proof["digest_verified"]:
        mismatched = _one(
            db,
            "SELECT ack_id FROM cf_digest_acks WHERE order_id=? AND site=? "
            "AND status='mismatch' LIMIT 1", (oid, site))
        decision = "digest_mismatch" if mismatched else "digest_not_acknowledged"
        return {"decision": decision, "order_id": oid, "site": site}

    ready_at = proof["proof_ready_at"]
    delivered_at = p.get("delivered_at")
    if delivered_at is None:
        delivered_at = ready_at if ready_at is not None else p.get("at")
    if ready_at is not None and delivered_at is not None and delivered_at < ready_at:
        return {"decision": "delivery_time_before_proof",
                "order_id": oid, "site": site,
                "delivered_at": delivered_at, "proof_ready_at": ready_at}
    accepted_at = p.get("at") if p.get("at") is not None else delivered_at

    db.execute(
        "INSERT INTO cf_acceptances(order_id,site,accepted_at,delivered_at,notified_at,"
        "digest,remediation_id,joint_id,basis) VALUES(?,?,?,?,?,?,?,?,?)",
        (oid, site, accepted_at, delivered_at, p.get("notified_at", delivered_at),
         order["digest"], p.get("remediation_id"), p.get("joint_id"),
         "customer_chunk_receipts_and_digest_ack"))

    if p.get("remediation_id"):
        db.execute(
            "UPDATE cf_remediations SET status='effective', closed_at=? "
            "WHERE remediation_id=? AND status='open'",
            (accepted_at, p["remediation_id"]))

    # Auto-grant the recomputable late relief exactly once per acceptance.
    grant = None
    credit = calculate_site_credit(db, oid, site, as_of=delivered_at)
    if credit:
        gid = p.get("grant_id") or f"credit:{oid}:{site}:acceptance"
        if not _one(db, "SELECT grant_id FROM cf_credit_grants WHERE grant_id=?", (gid,)):
            calc = {"formula": "daily_credit*sum(bytes_i*late_days_i)/total_bytes",
                    "delivered_at": delivered_at, "credit": credit}
            db.execute(
                "INSERT INTO cf_credit_grants(grant_id,order_id,site,amount,at,reason,"
                "remediation_id,correction_id,calc) VALUES(?,?,?,?,?,?,?,?,?)",
                (gid, oid, site, credit, accepted_at, "late_delivery_relief",
                 p.get("remediation_id"), None,
                 json.dumps(calc, sort_keys=True, ensure_ascii=False)))
            grant = gid
    return {"decision": "site_accepted", "order_id": oid, "site": site,
            "accepted_at": accepted_at, "delivered_at": delivered_at,
            "on_time": _on_time(order, delivered_at), "credit": credit,
            "credit_grant_id": grant}


sign_site = accept_site
accept = accept_site
verify_site = accept_site
sign_acceptance = accept_site


def _on_time(order, delivered_at):
    if delivered_at is None:
        return None
    return order["window_start"] <= delivered_at < order["window_end"]


def verify_delivery(db, order_id=None, site=None, **kwargs):
    """只读：某站点是否已有完整分片 + 整体摘要客户回执（不写签收）。"""
    if order_id is None:
        order_id = kwargs.get("order") or kwargs.get("id")
    if site is None:
        site = kwargs.get("site_id") or kwargs.get("dc")
    order = _load_order(db, order_id)
    if not order:
        return {"decision": "unknown_order", "order_id": order_id}
    if site not in _order_sites(db, order_id):
        return {"decision": "site_not_on_order", "site": site}
    proof = _site_proof(db, order, site)
    return {
        "decision": "verifiable" if proof["complete"] else "incomplete_content",
        "order_id": order_id, "site": site,
        "verifiable": proof["complete"],
        "missing_chunks": proof["missing_indexes"],
        "missing_bytes": proof["missing_bytes"],
        "digest_verified": proof["digest_verified"],
        "proof_ready_at": proof["proof_ready_at"],
    }


site_verifiable = verify_delivery


def site_accepted(db, order_id=None, site=None, **kwargs):
    row = _one(db, "SELECT 1 FROM cf_acceptances WHERE order_id=? AND site=?",
               (order_id, site))
    return row is not None


def order_accepted(db, order_id=None, **kwargs):
    order = _load_order(db, order_id)
    if not order:
        return False
    sites = _order_sites(db, order_id)
    done = {r["site"] for r in _all(
        db, "SELECT site FROM cf_acceptances WHERE order_id=?", (order_id,))}
    return bool(sites) and all(s in done for s in sites)


@_dictable
def complete_from_edge(db, payload=None, **kwargs):
    """明确禁止的捷径：宽限期后再发一张 CDN 发送记录不能宣布完成。"""
    p = _norm(_merge(payload, kwargs), "order_id", "site", "event_id", "at")
    oid, site = p.get("order_id"), p.get("site")
    order = _load_order(db, oid)
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    if p.get("event_id"):
        record_edge_send(db, p)
    proof = _site_proof(db, order, site)
    if _one(db, "SELECT 1 FROM cf_acceptances WHERE order_id=? AND site=?", (oid, site)):
        return {"decision": "site_already_accepted", "order_id": oid, "site": site}
    return {"decision": "edge_record_not_proof", "order_id": oid, "site": site,
            "missing_chunks": proof["missing_indexes"],
            "customer_verified_bytes": proof["verified_bytes"],
            "edge_claimed_bytes": naive_account_bytes(
                db, order["digest"], order["account"])}


declare_delivery_from_edge = complete_from_edge


@_dictable
def revise_delivery_time(db, payload=None, **kwargs):
    """交付/签收时间一经保留即不可追改；任何“改回合约时窗内”的请求都拒绝。"""
    p = _norm(_merge(payload, kwargs), "order_id", "site", "delivered_at",
              "accepted_at", "new_delivered_at")
    oid, site = p.get("order_id"), p.get("site")
    a = _one(db, "SELECT * FROM cf_acceptances WHERE order_id=? AND site=?", (oid, site))
    if not a:
        return {"decision": "no_acceptance_to_revise", "order_id": oid, "site": site}
    return {"decision": "delivery_time_immutable", "order_id": oid, "site": site,
            "delivered_at": a["delivered_at"], "accepted_at": a["accepted_at"],
            "on_time": _on_time(_load_order(db, oid), a["delivered_at"])}


# ---------------------------------------------------------------------------
# 6. Remediation cases (network patches vs cache devices)
# ---------------------------------------------------------------------------

@_dictable
def open_remediation(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "remediation_id", "order_id", "site",
              "method", "at", "device_id", "note")
    rid = p.get("remediation_id")
    oid, site = p.get("order_id"), p.get("site")
    method = p.get("method")
    if not rid:
        return {"decision": "invalid_payload", "reason": "remediation_id_required"}
    if method not in ("network_patch", "cache_device"):
        return {"decision": "invalid_remediation_method", "method": method}
    if not _load_order(db, oid):
        return {"decision": "unknown_order", "order_id": oid}
    if site not in _order_sites(db, oid):
        return {"decision": "site_not_on_order", "site": site}
    old = _one(db, "SELECT * FROM cf_remediations WHERE remediation_id=?", (rid,))
    if old:
        return {"decision": "reused" if old["method"] == method and old["site"] == site
                else "remediation_conflict", "remediation_id": rid}
    db.execute(
        "INSERT INTO cf_remediations(remediation_id,order_id,site,method,opened_at,"
        "closed_at,status,device_id,note) VALUES(?,?,?,?,?,?,?,?,?)",
        (rid, oid, site, method, p.get("at"), None, "open",
         p.get("device_id"), p.get("note")))
    return {"decision": "remediation_opened", "remediation_id": rid,
            "method": method, "order_id": oid, "site": site}


start_cure = open_remediation
choose_remedy = open_remediation


# ---------------------------------------------------------------------------
# 7. Encrypted cache devices: seals, customer-only decryption, custody, freight
# ---------------------------------------------------------------------------

@_dictable
def register_device(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "device_id", "order_id", "digest",
              "decryption_rights", "key_holder", "at")
    did = p.get("device_id")
    if not did:
        return {"decision": "invalid_payload", "reason": "device_id_required"}
    old = _one(db, "SELECT * FROM cf_devices WHERE device_id=?", (did,))
    fields = {"order_id": p.get("order_id"), "digest": p.get("digest"),
              "decryption_rights": p.get("decryption_rights", "customer_only"),
              "key_holder": p.get("key_holder") or p.get("account")}
    if old:
        same = all(old[k] == v for k, v in fields.items())
        return {"decision": "reused" if same else "device_conflict", "device_id": did}
    db.execute(
        "INSERT INTO cf_devices(device_id,order_id,digest,decryption_rights,key_holder,"
        "seal_status,status,issued_at,payload) VALUES(?,?,?,?,?,'intact','registered',?,?)",
        (did, fields["order_id"], fields["digest"], fields["decryption_rights"],
         fields["key_holder"], p.get("at"),
         json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
    return {"decision": "device_registered", "device_id": did,
            "decryption_rights": fields["decryption_rights"]}


@_dictable
def report_seal(db, payload=None, **kwargs):
    """登记封签事件。破损状态一旦出现即锁定为 broken，不能被后续“完好”洗白。"""
    p = _norm(_merge(payload, kwargs), "seal_event_id", "device_id", "seal_id",
              "status", "at", "note")
    eid, did = p.get("seal_event_id"), p.get("device_id")
    status = p.get("status")
    if not eid or not did:
        return {"decision": "invalid_payload"}
    if not _one(db, "SELECT 1 FROM cf_devices WHERE device_id=?", (did,)):
        return {"decision": "unknown_device", "device_id": did}
    old = _one(db, "SELECT 1 FROM cf_seal_events WHERE seal_event_id=?", (eid,))
    if old:
        return {"decision": "reused", "seal_event_id": eid}
    if status not in ("intact", "broken"):
        return {"decision": "invalid_seal_status", "status": status}
    db.execute("INSERT INTO cf_seal_events VALUES(?,?,?,?,?,?)",
               (eid, did, p.get("seal_id"), status, p.get("at"), p.get("note")))
    if status == "broken":
        db.execute(
            "UPDATE cf_devices SET seal_status='broken', status='tampered' WHERE device_id=?",
            (did,))
        return {"decision": "seal_broken_recorded", "device_id": did,
                "seal_id": p.get("seal_id")}
    return {"decision": "seal_event_recorded", "device_id": did, "status": status}


update_seal = report_seal


@_dictable
def custody_checkpoint(db, payload=None, **kwargs):
    """承运/第三方仓库交接证据：封签完好且解密权仍只归该客户。"""
    p = _norm(_merge(payload, kwargs), "checkpoint_id", "device_id", "at",
              "party", "kind", "code", "seal_id", "seal_intact",
              "customer_key_only", "proof_ref")
    cid = p.get("checkpoint_id")
    if not cid:
        return {"decision": "invalid_payload", "reason": "checkpoint_id_required"}
    if not _one(db, "SELECT 1 FROM cf_devices WHERE device_id=?", (p.get("device_id"),)):
        return {"decision": "unknown_device", "device_id": p.get("device_id")}
    old = _one(db, "SELECT 1 FROM cf_custody WHERE checkpoint_id=?", (cid,))
    if old:
        return {"decision": "reused", "checkpoint_id": cid}
    seal_intact = p.get("seal_intact")
    if seal_intact is None:
        seal_intact = p.get("seal_ok")
    key_only = p.get("customer_key_only")
    if key_only is None:
        key_only = p.get("decryption_customer_only")

    def _tri(value):
        return None if value is None else (1 if value else 0)

    db.execute(
        "INSERT INTO cf_custody(checkpoint_id,device_id,at,party,kind,code,seal_id,"
        "seal_intact,customer_key_only,proof_ref,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (cid, p.get("device_id"), p.get("at"), p.get("party"), p.get("kind"),
         p.get("code"), p.get("seal_id"),
         _tri(seal_intact), _tri(key_only), p.get("proof_ref"),
         json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)))
    return {"decision": "custody_recorded", "checkpoint_id": cid,
            "seal_intact": None if seal_intact is None else bool(seal_intact),
            "customer_key_only": None if key_only is None else bool(key_only)}


warehouse_checkpoint = custody_checkpoint


@_dictable
def ship_device(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "shipment_id", "device_id", "order_id",
              "site", "direction", "carrier", "at", "cost", "currency",
              "billed_to", "via", "status")
    sid = p.get("shipment_id")
    did = p.get("device_id")
    if not sid or not did:
        return {"decision": "invalid_payload"}
    if not _one(db, "SELECT 1 FROM cf_devices WHERE device_id=?", (did,)):
        return {"decision": "unknown_device", "device_id": did}
    old = _one(db, "SELECT 1 FROM cf_shipments WHERE shipment_id=?", (sid,))
    if old:
        return {"decision": "reused", "shipment_id": sid}
    via = p.get("via") or []
    if isinstance(via, str):
        via = [via]
    direction = p.get("direction", "outbound")
    db.execute(
        "INSERT INTO cf_shipments(shipment_id,device_id,order_id,site,direction,carrier,"
        "at,cost,currency,billed_to,via,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, did, p.get("order_id"), p.get("site"), direction, p.get("carrier"),
         p.get("at"), p.get("cost", 0) or 0, p.get("currency", "CNY"),
         p.get("billed_to", "platform"), json.dumps(list(via), ensure_ascii=False),
         p.get("status", "shipped")))
    if direction == "return":
        db.execute("UPDATE cf_devices SET status='returned' WHERE device_id=?", (did,))
    else:
        db.execute("UPDATE cf_devices SET status='in_transit' WHERE device_id=?", (did,))
    return {"decision": "device_shipped" if direction == "outbound" else "device_return_recorded",
            "shipment_id": sid, "direction": direction,
            "cost": p.get("cost", 0) or 0, "billed_to": p.get("billed_to", "platform")}


@_dictable
def return_device(db, payload=None, **kwargs):
    kwargs.setdefault("direction", "return")
    if isinstance(payload, dict):
        payload = {**payload, "direction": payload.get("direction", "return")}
    return ship_device(db, payload, **kwargs)


@_dictable
def verify_device(db, payload=None, **kwargs):
    """客户现场核验加密缓存设备。

    成功条件：设备摘要 == 订单承诺；封签未破损；申报途经的第三方仓库都有
    “封签完好 + 客户独占解密权”证据；设备解密权约定为 customer_only。
    成功后由现场核验派生绑定站点的客户分片/摘要回执（设备只是补交载体，
    验收仍只认站点内容证据）。
    """
    p = _norm(_merge(payload, kwargs), "verification_id", "device_id",
              "order_id", "site", "at", "verified_indexes", "all_chunks",
              "chunks_verified")
    vid, did = p.get("verification_id"), p.get("device_id")
    oid, site = p.get("order_id"), p.get("site")
    if not vid or not did:
        return {"decision": "invalid_payload"}
    device = _one(db, "SELECT * FROM cf_devices WHERE device_id=?", (did,))
    if not device:
        return {"decision": "unknown_device", "device_id": did}
    order = _load_order(db, oid or device["order_id"])
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    oid = order["order_id"]
    if site not in _order_sites(db, oid):
        return {"decision": "site_not_on_order", "site": site}
    if _one(db, "SELECT 1 FROM cf_device_verifications WHERE verification_id=?", (vid,)):
        prior = _one(db, "SELECT * FROM cf_device_verifications WHERE verification_id=?", (vid,))
        return {"decision": "reused", "verification_id": vid, "outcome": prior["outcome"]}

    def fail(reason, decision):
        db.execute(
            "INSERT INTO cf_device_verifications(verification_id,device_id,order_id,site,"
            "at,outcome,reason,verified_indexes) VALUES(?,?,?,?,?,?,?,?)",
            (vid, did, oid, site, p.get("at"), "rejected", reason, None))
        db.execute(
            "UPDATE cf_remediations SET status='failed' WHERE device_id=? AND status='open'",
            (did,))
        db.execute("UPDATE cf_devices SET status='rejected' WHERE device_id=? "
                   "AND status!='returned'", (did,))
        return {"decision": decision, "device_id": did, "reason": reason}

    if device["digest"] and device["digest"] != order["digest"]:
        return fail("device digest does not match order commitment", "device_digest_mismatch")
    broken = _one(db, "SELECT 1 FROM cf_seal_events WHERE device_id=? AND status='broken' LIMIT 1",
                  (did,))
    if broken or device["seal_status"] == "broken":
        return fail("tamper-evident seal is broken", "device_seal_broken")
    if device["decryption_rights"] != "customer_only":
        return fail("decryption rights are not customer-only", "device_key_not_customer_only")

    shipments = _all(db, "SELECT * FROM cf_shipments WHERE device_id=? ORDER BY at", (did,))
    declared_via = set()
    for s in shipments:
        try:
            declared_via.update(json.loads(s["via"] or "[]"))
        except (ValueError, TypeError):
            pass
    checkpoints = _all(db, "SELECT * FROM cf_custody WHERE device_id=?", (did,))
    by_code = {c["code"]: c for c in checkpoints if c["code"]}

    def custody_failure(c):
        # Explicit bad evidence is distinguished from missing proof.
        if c["seal_intact"] == 0:
            return "device_seal_broken", "seal reported broken during custody"
        if c["customer_key_only"] == 0:
            return "device_key_not_customer_only", "decryption right not customer-only"
        if c["seal_intact"] is None or c["customer_key_only"] is None \
                or not c["proof_ref"]:
            return "custody_proof_missing", "incomplete seal/key custody proof"
        return None

    for code in declared_via:
        c = by_code.get(code)
        if not c:
            return fail(f"missing custody proof at {code}", "custody_proof_missing")
        problem = custody_failure(c)
        if problem:
            decision, reason = problem
            return fail(f"{reason} at {code}", decision)
    for c in checkpoints:
        if c["kind"] == "third_party_warehouse" \
                or "warehouse" in (c["party"] or "").lower():
            problem = custody_failure(c)
            if problem:
                decision, reason = problem
                return fail(reason, decision)

    specs = _chunk_specs(db, oid)
    indexes = p.get("verified_indexes", p.get("chunks_verified"))
    if p.get("all_chunks") or indexes is None:
        indexes = [c["idx"] for c in specs]
    indexes = [int(i) for i in indexes]
    spec_by_idx = {c["idx"]: c for c in specs}

    derived = []
    for idx in indexes:
        spec = spec_by_idx.get(idx)
        if not spec:
            continue
        exists = _one(
            db,
            "SELECT 1 FROM cf_receipts WHERE order_id=? AND site=? AND idx=? "
            "AND status='verified' LIMIT 1", (oid, site, idx))
        if exists:
            continue
        rid = f"devrcpt:{vid}:{idx}"
        db.execute(
            "INSERT INTO cf_receipts(receipt_id,order_id,site,idx,chunk_digest,bytes,at,via,"
            "status,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, oid, site, idx, spec["chunk_digest"], spec["bytes"], p.get("at"),
             f"device:{did}", "verified",
             json.dumps({"derived_from_device_verification": vid}, sort_keys=True)))
        derived.append(idx)
    aid = f"devack:{vid}"
    if not _one(db, "SELECT 1 FROM cf_digest_acks WHERE ack_id=?", (aid,)):
        db.execute(
            "INSERT INTO cf_digest_acks(ack_id,order_id,site,digest,at,via,status,payload) "
            "VALUES(?,?,?,?,?,?,'verified',?)",
            (aid, oid, site, order["digest"], p.get("at"), f"device:{did}",
             json.dumps({"derived_from_device_verification": vid}, sort_keys=True)))

    db.execute(
        "INSERT INTO cf_device_verifications(verification_id,device_id,order_id,site,at,"
        "outcome,reason,verified_indexes) VALUES(?,?,?,?,?,'verified',NULL,?)",
        (vid, did, oid, site, p.get("at"), json.dumps(indexes)))
    db.execute("UPDATE cf_devices SET status='verified' WHERE device_id=?", (did,))
    return {"decision": "device_verified", "device_id": did, "order_id": oid,
            "site": site, "derived_receipts": derived}


on_site_verify = verify_device


@_dictable
def joint_accept(db, payload=None, **kwargs):
    """缓存设备安排下的订单级一并验收。

    不撤回/覆盖任何站点既有签收；只补齐尚缺且证据完整的站点，并写一条联合验收
    记录。若所有站点都已验收（例如网络补片抢先完成），不产生第二次验收。
    """
    p = _norm(_merge(payload, kwargs), "joint_id", "order_id", "device_id",
              "verification_id", "at", "remediation_id")
    oid = p.get("order_id")
    order = _load_order(db, oid)
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    sites = _order_sites(db, oid)
    before = {r["site"] for r in _all(
        db, "SELECT site FROM cf_acceptances WHERE order_id=?", (oid,))}

    vid = p.get("verification_id")
    if vid:
        v = _one(db, "SELECT * FROM cf_device_verifications WHERE verification_id=?", (vid,))
        if not v or v["outcome"] != "verified":
            reason = v["reason"] if v else "no_verification"
            decision = "device_not_verified"
            if v and "seal" in (v["reason"] or ""):
                decision = "device_seal_broken"
            return {"decision": decision, "order_id": oid, "reason": reason}

    remediation_id = p.get("remediation_id")
    if not remediation_id and p.get("device_id"):
        rm = _one(db,
                  "SELECT remediation_id FROM cf_remediations WHERE order_id=? AND device_id=? "
                  "AND method='cache_device' ORDER BY opened_at LIMIT 1",
                  (oid, p.get("device_id")))
        remediation_id = rm["remediation_id"] if rm else None

    joint_id = p.get("joint_id") or f"joint:{oid}:{p.get('device_id') or remediation_id or 'x'}"
    accepted_now = []
    blocked = {}
    for site in sites:
        if site in before:
            continue
        res = accept_site(db, {"order_id": oid, "site": site, "at": p.get("at"),
                               "remediation_id": remediation_id, "joint_id": joint_id})
        if res["decision"] == "site_accepted":
            accepted_now.append(site)
        else:
            blocked[site] = res["decision"]
    after = {r["site"] for r in _all(
        db, "SELECT site FROM cf_acceptances WHERE order_id=?", (oid,))}

    if accepted_now:
        db.execute(
            "INSERT OR REPLACE INTO cf_joint_acceptances(joint_id,order_id,device_id,at,sites,"
            "remediation_id) VALUES(?,?,?,?,?,?)",
            (joint_id, oid, p.get("device_id"), p.get("at"),
             json.dumps(sorted(after)), remediation_id))
        if remediation_id:
            db.execute("UPDATE cf_remediations SET status='effective',closed_at=? "
                       "WHERE remediation_id=?", (p.get("at"), remediation_id))
        return {"decision": "jointly_accepted", "joint_id": joint_id,
                "accepted_now": accepted_now, "sites": sorted(after)}
    if len(after) == len(sites):
        return {"decision": "already_accepted", "order_id": oid, "sites": sorted(after),
                "note": "no_second_acceptance"}
    return {"decision": "joint_acceptance_blocked", "blocked": blocked}


# ---------------------------------------------------------------------------
# 8. Vendor bandwidth charges (originals retained, payment tracked)
# ---------------------------------------------------------------------------

@_dictable
def rename_handoff(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "node_id", "name", "new_name", "at")
    node, name = p.get("node_id"), p.get("name") or p.get("new_name")
    if not node or not name:
        return {"decision": "invalid_payload"}
    db.execute("INSERT INTO cf_handoffs(node_id,current_name) VALUES(?,?) "
               "ON CONFLICT(node_id) DO UPDATE SET current_name=excluded.current_name",
               (node, name))
    db.execute("INSERT OR IGNORE INTO cf_handoff_aliases(node_id,name,at) VALUES(?,?,?)",
               (node, name, p.get("at")))
    # Renaming a handoff must not reassign or rewrite charge originals.
    return {"decision": "handoff_renamed", "node_id": node, "current_name": name}


@_dictable
def record_vendor_charge(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "charge_id", "vendor", "node_id",
              "handoff_name", "digest", "order_id", "amount", "currency",
              "period_start", "period_end", "at")
    cid = p.get("charge_id")
    if not cid or p.get("amount") is None:
        return {"decision": "invalid_payload"}
    old = _one(db, "SELECT * FROM cf_vendor_charges WHERE charge_id=?", (cid,))
    if old:
        same_amount = str(old["amount"]) == str(p["amount"])
        return {"decision": "reused" if same_amount and old["node_id"] == p.get("node_id")
                else "charge_identity_conflict", "charge_id": cid}
    node = p.get("node_id")
    handoff_name = p.get("handoff_name")
    if handoff_name is None and node:
        h = _one(db, "SELECT current_name FROM cf_handoffs WHERE node_id=?", (node,))
        handoff_name = h["current_name"] if h else node
    original = json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)
    db.execute(
        "INSERT INTO cf_vendor_charges(charge_id,vendor,node_id,handoff_name,digest,order_id,"
        "amount,currency,period_start,period_end,at,status,paid_at,original_payload) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,'recorded',NULL,?)",
        (cid, p.get("vendor"), node, handoff_name, p.get("digest"), p.get("order_id"),
         p["amount"], p.get("currency", "CNY"), p.get("period_start"),
         p.get("period_end"), p.get("at"), original))
    return {"decision": "vendor_charge_recorded", "charge_id": cid,
            "amount": p["amount"], "status": "recorded"}


@_dictable
def pay_vendor_charge(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "charge_id", "paid_at", "at")
    cid = p.get("charge_id")
    c = _one(db, "SELECT * FROM cf_vendor_charges WHERE charge_id=?", (cid,))
    if not c:
        return {"decision": "unknown_charge", "charge_id": cid}
    if c["status"] == "paid":
        return {"decision": "charge_already_paid", "charge_id": cid,
                "paid_at": c["paid_at"], "amount": c["amount"]}
    paid_at = p.get("paid_at") if p.get("paid_at") is not None else p.get("at")
    db.execute("UPDATE cf_vendor_charges SET status='paid', paid_at=? WHERE charge_id=?",
               (paid_at, cid))
    return {"decision": "charge_paid", "charge_id": cid,
            "paid_at": paid_at, "amount": c["amount"]}


# ---------------------------------------------------------------------------
# 9. Post-signoff shortfalls -> breach makeup + correction, never backdating
# ---------------------------------------------------------------------------

@_dictable
def report_shortfall(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "correction_id", "order_id", "site", "at",
              "missing_indexes", "invalidate_receipt_id", "note", "kind")
    cid, oid, site = p.get("correction_id"), p.get("order_id"), p.get("site")
    if not cid:
        return {"decision": "invalid_payload", "reason": "correction_id_required"}
    a = _one(db, "SELECT * FROM cf_acceptances WHERE order_id=? AND site=?", (oid, site))
    if not a:
        return {"decision": "no_acceptance_on_record", "order_id": oid, "site": site}
    old = _one(db, "SELECT 1 FROM cf_corrections WHERE correction_id=?", (cid,))
    if old:
        return {"decision": "reused", "correction_id": cid}
    missing = p.get("missing_indexes") or []
    if isinstance(missing, (int, str)):
        missing = [missing]
    db.execute(
        "INSERT INTO cf_corrections(correction_id,order_id,site,at,kind,missing_indexes,"
        "invalidate_receipt_id,original_delivered_at,original_accepted_at,note) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (cid, oid, site, p.get("at"), p.get("kind", "post_acceptance_shortfall"),
         json.dumps([int(i) for i in missing], ensure_ascii=False),
         p.get("invalidate_receipt_id"), a["delivered_at"], a["accepted_at"], p.get("note")))
    if p.get("invalidate_receipt_id"):
        # Retain the original receipt row, but stop counting it as proof.
        db.execute("UPDATE cf_receipts SET status='challenged' WHERE receipt_id=?",
                   (p["invalidate_receipt_id"],))
    return {"decision": "shortfall_recorded_breach_makeup_required",
            "correction_id": cid, "order_id": oid, "site": site,
            "original_delivered_at": a["delivered_at"],
            "delivery_time_unchanged": True}


register_missing_after_acceptance = report_shortfall


@_dictable
def grant_credit(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs), "grant_id", "order_id", "site", "amount",
              "at", "reason", "remediation_id", "correction_id")
    gid = p.get("grant_id")
    if not gid or p.get("amount") is None:
        return {"decision": "invalid_payload"}
    old = _one(db, "SELECT 1 FROM cf_credit_grants WHERE grant_id=?", (gid,))
    if old:
        return {"decision": "reused", "grant_id": gid}
    calc = p.get("calc")
    if not isinstance(calc, str):
        calc = json.dumps(calc or {"amount": p["amount"], "manual": True},
                          sort_keys=True, ensure_ascii=False, default=str)
    db.execute(
        "INSERT INTO cf_credit_grants(grant_id,order_id,site,amount,at,reason,"
        "remediation_id,correction_id,calc) VALUES(?,?,?,?,?,?,?,?,?)",
        (gid, p.get("order_id"), p.get("site"), p["amount"], p.get("at"),
         p.get("reason", "correction_relief"), p.get("remediation_id"),
         p.get("correction_id"), calc))
    return {"decision": "credit_granted", "grant_id": gid, "amount": p["amount"]}


# ---------------------------------------------------------------------------
# 10. Recomputable conclusion / scorecard
# ---------------------------------------------------------------------------

def _site_report(db, order, site, as_of=None):
    proof = _site_proof(db, order, site)
    acc = _one(db, "SELECT * FROM cf_acceptances WHERE order_id=? AND site=?",
               (order["order_id"], site))
    marks = _one(db, "SELECT * FROM cf_portal_marks WHERE order_id=? AND site=?",
                 (order["order_id"], site))
    grants = _all(db,
                  "SELECT * FROM cf_credit_grants WHERE order_id=? AND site=? ORDER BY rowid",
                  (order["order_id"], site))
    corrections = _all(db,
                       "SELECT * FROM cf_corrections WHERE order_id=? AND site=? ORDER BY rowid",
                       (order["order_id"], site))
    calculated = calculate_site_credit(db, order["order_id"], site, as_of=as_of)
    if acc:
        status = "accepted"
        if corrections:
            status = "accepted_with_open_breach_correction" if proof["missing_indexes"] \
                else "accepted_corrected"
    elif proof["complete"]:
        status = "complete_awaiting_signoff"
    elif as_of is not None and order["grace_end"] is not None and as_of > order["grace_end"]:
        status = "grace_exhausted_breach"
    else:
        status = "incomplete"
    open_correction_ids = []
    for c in corrections:
        scoped = json.loads(c["missing_indexes"] or "[]")
        if any(i in proof["missing_indexes"] for i in scoped) or (
                not scoped and proof["missing_indexes"]):
            open_correction_ids.append(c["correction_id"])
    return {
        "site": site,
        "status": status,
        "accepted": acc is not None,
        "accepted_at": acc["accepted_at"] if acc else None,
        "delivered_at": acc["delivered_at"] if acc else None,
        "notified_at": acc["notified_at"] if acc else None,
        "on_time": _on_time(order, acc["delivered_at"]) if acc else None,
        "acceptance_immutable": acc is not None,
        "expected_chunks": len(proof["expected_indexes"]),
        "verified_chunks": len(proof["verified_indexes"]),
        "verified_indexes": proof["verified_indexes"],
        "missing_chunks": proof["missing_indexes"],
        "missing_indexes": proof["missing_indexes"],
        "total_bytes": proof["total_bytes"],
        "verified_bytes": proof["verified_bytes"],
        "missing_bytes": proof["missing_bytes"],
        "digest_verified": proof["digest_verified"],
        "proof_ready_at": proof["proof_ready_at"],
        "calculated_credit": calculated,
        "credit_granted": sum(g["amount"] for g in grants),
        "credit_grants": [g["grant_id"] for g in grants],
        "open_corrections": open_correction_ids,
        "corrections": [c["correction_id"] for c in corrections],
        "portal_marked_accepted": bool(marks and marks["marked_accepted"]),
        "portal_overstatement": bool(marks and marks["marked_accepted"] and not acc),
        "remediation_id": acc["remediation_id"] if acc else None,
        "joint_id": acc["joint_id"] if acc else None,
    }


@_dictable
def remediation_scorecard(db, order_id=None, site=None, **kwargs):
    """按补交方式汇总：可用时间、运费、网络用量与减免，两种安排可直接比较。"""
    if order_id is None and isinstance(kwargs.get("payload"), str):
        order_id = kwargs["payload"]
    if order_id is None:
        order_id = kwargs.get("order") or kwargs.get("oid") or kwargs.get("id")
    if site is None:
        site = kwargs.get("site_id") or kwargs.get("dc")
    order = _load_order(db, order_id)
    if not order:
        return {"decision": "unknown_order", "order_id": order_id}
    rms = _all(db, "SELECT * FROM cf_remediations WHERE order_id=? "
                    + ("AND site=? " if site else "") + "ORDER BY opened_at,rowid",
               (order_id,) + ((site,) if site else ()))
    cards = []
    for rm in rms:
        shipments = _all(db, "SELECT * FROM cf_shipments WHERE device_id=? ORDER BY rowid",
                         (rm["device_id"],)) if rm["device_id"] else []
        shipping = sum(s["cost"] for s in shipments)
        outbound = sum(s["cost"] for s in shipments if s["direction"] == "outbound")
        returns = sum(s["cost"] for s in shipments if s["direction"] == "return")
        acc = _one(db, "SELECT * FROM cf_acceptances WHERE order_id=? AND site=?",
                   (order_id, rm["site"]))
        # Network bytes delivered under cure: late-window verified receipts by via.
        receipts = _all(
            db,
            "SELECT r.* FROM cf_receipts r WHERE r.order_id=? AND r.site=? "
            "AND r.status='verified'", (order_id, rm["site"]))
        net_bytes = 0
        device_bytes = 0
        for r in receipts:
            late = r["at"] is not None and r["at"] >= order["window_end"]
            if str(r["via"]).startswith("device:"):
                device_bytes += r["bytes"]
            elif late:
                net_bytes += r["bytes"]
        proof = _site_proof(db, order, rm["site"])
        plan_network_required = _missing_at_open(db, order, rm) \
            if rm["method"] == "network_patch" else 0
        effective = bool(acc and acc["remediation_id"] == rm["remediation_id"])
        grants = _all(db, "SELECT COALESCE(SUM(amount),0) AS n FROM cf_credit_grants "
                          "WHERE remediation_id=?", (rm["remediation_id"],))
        cards.append({
            "remediation_id": rm["remediation_id"],
            "site": rm["site"],
            "method": rm["method"],
            "status": rm["status"],
            "device_id": rm["device_id"],
            "opened_at": rm["opened_at"],
            "customer_available_at": acc["delivered_at"] if effective else None,
            "effective": effective,
            "shipping_cost": shipping,
            "outbound_freight": outbound,
            "return_freight": returns,
            "shipping_billed_to": "platform",
            "network_bytes_required_for_plan": plan_network_required,
            "network_bytes_remaining": proof["missing_bytes"],
            "network_bytes_delivered_cure": net_bytes,
            "device_bytes_delivered": device_bytes,
            "credit_linked": grants[0]["n"] if grants else 0,
        })
    return {"decision": "scorecard", "order_id": order_id, "arrangements": cards}


def _missing_at_open(db, order, rm):
    """Missing bytes that motivated the case (approximated by current late bytes)."""
    proof = _site_proof(db, order, rm["site"])
    if rm["method"] == "cache_device":
        return 0
    # bytes whose valid receipt arrived after window_end + still missing
    late = _all(db,
                "SELECT COALESCE(SUM(r.bytes),0) AS n FROM cf_receipts r "
                "WHERE r.order_id=? AND r.site=? AND r.status='verified' "
                "AND r.at IS NOT NULL AND r.at>=?",
                (order["order_id"], rm["site"], order["window_end"]))
    return late[0]["n"] + proof["missing_bytes"]


def fulfillment_report(db, payload=None, **kwargs):
    """可复算的履约结论。``at`` 用于判断宽限期是否已经过尽。"""
    p = _norm(_merge(payload, kwargs, str_key="order_id"), "order_id", "at")
    oid = p.get("order_id")
    as_of = p.get("at")
    order = _load_order(db, oid)
    if not order:
        return {"decision": "unknown_order", "order_id": oid}
    sites = _order_sites(db, oid)
    site_reports = {s: _site_report(db, order, s, as_of) for s in sites}
    accepted = [s for s in sites if site_reports[s]["accepted"]]
    overstatements = [s for s in sites if site_reports[s]["portal_overstatement"]]

    charges = _all(
        db,
        "SELECT * FROM cf_vendor_charges WHERE order_id=? "
        "OR (order_id IS NULL AND digest=?)",
        (oid, order["digest"]))
    vendor_total = sum(c["amount"] for c in charges)
    vendor_paid = sum(c["amount"] for c in charges if c["status"] == "paid")

    shipments = _all(
        db,
        "SELECT * FROM cf_shipments WHERE order_id=? "
        "OR device_id IN (SELECT device_id FROM cf_devices WHERE order_id=?)",
        (oid, oid))
    shipping_platform = sum(x["cost"] for x in shipments if x["billed_to"] == "platform")
    shipping_customer = sum(x["cost"] for x in shipments if x["billed_to"] == "customer")

    credit_total = _one(db,
                        "SELECT COALESCE(SUM(amount),0) AS n FROM cf_credit_grants WHERE order_id=?",
                        (oid,))["n"]
    calculated_total = sum(site_reports[s]["calculated_credit"] for s in sites)

    joint = _all(db, "SELECT * FROM cf_joint_acceptances WHERE order_id=? ORDER BY rowid", (oid,))
    rms = _all(db, "SELECT * FROM cf_remediations WHERE order_id=? ORDER BY rowid", (oid,))

    grace_exhausted = any(site_reports[s]["status"] == "grace_exhausted_breach" for s in sites)
    if len(accepted) == len(sites):
        status = "accepted"
    elif grace_exhausted:
        status = "breach"
    elif accepted:
        status = "partially_accepted"
    else:
        status = "in_delivery"

    edge_claimed = _one(
        db,
        "SELECT COALESCE(SUM(bytes_sent),0) AS n, COUNT(*) AS c FROM cf_edge_sends "
        "WHERE order_id=? OR (digest=? AND account=?)",
        (oid, order["digest"], order["account"]))
    report = {
        "decision": "fulfillment_report",
        "order_id": oid,
        "account": order["account"],
        "digest": order["digest"],
        "status": status,
        "at": as_of,
        "window": {"start": order["window_start"], "end": order["window_end"],
                   "grace_end": order["grace_end"]},
        "sites": site_reports,
        "site_order": sites,
        "accepted_sites": accepted,
        "accepted_count": len(accepted),
        "all_accepted": len(accepted) == len(sites),
        "portal_overstatement_sites": overstatements,
        "grace_exhausted": grace_exhausted,
        "edge": {
            "records": edge_claimed["c"],
            "claimed_bytes_sum": edge_claimed["n"],
            "naive_provisional_bytes": naive_account_bytes(
                db, order["digest"], order["account"]),
            "proof": False,
        },
        "credit": {
            "granted_total": credit_total,
            "calculated_total": calculated_total,
            "by_site": {s: site_reports[s]["credit_granted"] for s in sites},
        },
        "costs": {
            "shipping_platform": shipping_platform,
            "shipping_customer": shipping_customer,
            "shipping_total": shipping_platform + shipping_customer,
            "vendor_charges_total": vendor_total,
            "vendor_charges_paid": vendor_paid,
            "vendor_all_paid": bool(charges)
                and all(c["status"] == "paid" for c in charges),
        },
        "vendor_charges": [
            {"charge_id": c["charge_id"], "vendor": c["vendor"],
             "node_id": c["node_id"], "handoff_name_original": c["handoff_name"],
             "amount": c["amount"], "currency": c["currency"],
             "status": c["status"], "paid_at": c["paid_at"]}
            for c in charges
        ],
        "joint_acceptances": [j["joint_id"] for j in joint],
        "remediations": [r["remediation_id"] for r in rms],
        "scorecard": remediation_scorecard(db, oid)["arrangements"],
    }
    return report


conclusion = fulfillment_report
assess = fulfillment_report
evaluate = fulfillment_report
get_report = fulfillment_report
report = fulfillment_report
delivery_report = fulfillment_report


def settlement_digest(db, order_id, at=None):
    """Canonical SHA-256 over the recomputable conclusion (for audit/replay)."""
    rep = fulfillment_report(db, order_id=order_id, at=at)
    blob = json.dumps(rep, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@_dictable
def settlement_hash(db, payload=None, **kwargs):
    p = _norm(_merge(payload, kwargs, str_key="order_id"), "order_id", "at")
    oid = p.get("order_id")
    if not _load_order(db, oid):
        return {"decision": "unknown_order", "order_id": oid}
    digest = settlement_digest(db, oid, p.get("at"))
    return {"decision": "settlement_hash", "order_id": oid,
            "sha256": f"sha256:{digest}"}


build_conclusion = fulfillment_report
settle_order = fulfillment_report


# ---------------------------------------------------------------------------
# run(db, x) op dispatch (house style)
# ---------------------------------------------------------------------------

OPS = {
    "commit_order": commit_order,
    "create_order": commit_order,
    "register_order": commit_order,
    "order": commit_order,
    "edge_send": record_edge_send,
    "record_edge_send": record_edge_send,
    "send": record_edge_send,
    "lose_edge_cache": lose_edge_cache,
    "edge_cache_lost": lose_edge_cache,
    "edge_cache_loss": lose_edge_cache,
    "chunk_receipt": record_chunk_receipt,
    "receive_chunk": record_chunk_receipt,
    "receipt": record_chunk_receipt,
    "record_receipt": record_chunk_receipt,
    "digest_ack": record_digest_ack,
    "ack_digest": record_digest_ack,
    "ack": record_digest_ack,
    "portal_mark": mark_portal_accepted,
    "mark_portal": mark_portal_accepted,
    "accept_site": accept_site,
    "accept": accept_site,
    "sign_site": accept_site,
    "complete_from_edge": complete_from_edge,
    "edge_complete": complete_from_edge,
    "revise_delivery_time": revise_delivery_time,
    "backdate_delivery": revise_delivery_time,
    "open_remediation": open_remediation,
    "remediate": open_remediation,
    "register_device": register_device,
    "device": register_device,
    "report_seal": report_seal,
    "seal_event": report_seal,
    "custody_checkpoint": custody_checkpoint,
    "custody": custody_checkpoint,
    "warehouse_checkpoint": custody_checkpoint,
    "ship_device": ship_device,
    "ship": ship_device,
    "return_device": return_device,
    "verify_device": verify_device,
    "device_verify": verify_device,
    "joint_accept": joint_accept,
    "joint_acceptance": joint_accept,
    "rename_handoff": rename_handoff,
    "handoff_rename": rename_handoff,
    "record_vendor_charge": record_vendor_charge,
    "vendor_charge": record_vendor_charge,
    "pay_vendor_charge": pay_vendor_charge,
    "pay_charge": pay_vendor_charge,
    "report_shortfall": report_shortfall,
    "shortfall": report_shortfall,
    "grant_credit": grant_credit,
    "credit": grant_credit,
    "report": fulfillment_report,
    "fulfillment_report": fulfillment_report,
    "conclusion": fulfillment_report,
    "status": fulfillment_report,
    "scorecard": remediation_scorecard,
    "remediation_scorecard": remediation_scorecard,
    "calculate_credit": calculate_site_credit,
    "settlement_hash": settlement_hash,
    "hash": settlement_hash,
}


OP_PRIMARY_ID = {
    "commit_order": "order_id", "create_order": "order_id",
    "register_order": "order_id", "order": "order_id",
    "edge_send": "event_id", "record_edge_send": "event_id", "send": "event_id",
    "chunk_receipt": "receipt_id", "receive_chunk": "receipt_id",
    "receipt": "receipt_id", "record_receipt": "receipt_id",
    "digest_ack": "ack_id", "ack_digest": "ack_id", "ack": "ack_id",
    "open_remediation": "remediation_id", "remediate": "remediation_id",
    "register_device": "device_id", "device": "device_id",
    "report_seal": "seal_event_id", "seal_event": "seal_event_id",
    "custody_checkpoint": "checkpoint_id", "custody": "checkpoint_id",
    "warehouse_checkpoint": "checkpoint_id",
    "ship_device": "shipment_id", "ship": "shipment_id",
    "return_device": "shipment_id",
    "verify_device": "verification_id", "device_verify": "verification_id",
    "joint_accept": "joint_id", "joint_acceptance": "joint_id",
    "record_vendor_charge": "charge_id", "vendor_charge": "charge_id",
    "pay_vendor_charge": "charge_id", "pay_charge": "charge_id",
    "report_shortfall": "correction_id", "shortfall": "correction_id",
    "grant_credit": "grant_id", "credit": "grant_id",
    "report": "order_id", "fulfillment_report": "order_id",
    "conclusion": "order_id", "status": "order_id",
    "settlement_hash": "order_id", "hash": "order_id",
    "lose_edge_cache": "order_id", "edge_cache_lost": "order_id",
    "edge_cache_loss": "order_id",
    "scorecard": "order_id", "remediation_scorecard": "order_id",
    "calculate_credit": "order_id",
}


def run(db, x):
    if not isinstance(x, dict):
        raise ValueError("payload must be a dict")
    op = x.get("op")
    handler = OPS.get(op)
    if handler is None:
        raise ValueError(op)
    ensure_schema(db)
    payload = dict(x)
    # House style names every aggregate identifier ``id``; map it to this op's
    # primary identifier without letting it leak into unrelated id fields.
    primary = OP_PRIMARY_ID.get(op)
    if primary and payload.get(primary) is None and payload.get("id") is not None:
        payload[primary] = payload["id"]
    return handler(db, payload)


# ---------------------------------------------------------------------------
# Class facade for callers that prefer a ledger/service object
# ---------------------------------------------------------------------------

class CustomerFulfillment:
    """Thin object facade: ``CustomerFulfillment(db).commit_order(...)``."""

    def __init__(self, db):
        self.db = db
        ensure_schema(db)

    def run(self, payload):
        return run(self.db, payload)

    def __getattr__(self, name):
        fn = globals().get(name)
        if callable(fn):
            return functools.partial(fn, self.db)
        raise AttributeError(name)


FulfillmentService = CustomerFulfillment
FulfillmentLedger = CustomerFulfillment
Fulfillment = CustomerFulfillment
FulfillmentEngine = CustomerFulfillment
CustomerFulfillmentService = CustomerFulfillment

# Additional functional naming aliases for callers/tests using domain verbs.
evaluate_order = fulfillment_report
assess_order = fulfillment_report
get_conclusion = fulfillment_report
build_report = fulfillment_report
delivery_conclusion = fulfillment_report
site_report = fulfillment_report
customer_receipt = record_chunk_receipt
add_customer_receipt = record_chunk_receipt
record_customer_receipt = record_chunk_receipt
whole_digest_ack = record_digest_ack
acknowledge_whole_digest = record_digest_ack
create_remediation = open_remediation
dispatch_device = ship_device
on_site_device_verification = verify_device
calculate_relief = calculate_site_credit
daily_relief = calculate_site_credit
relief_for_site = calculate_site_credit
