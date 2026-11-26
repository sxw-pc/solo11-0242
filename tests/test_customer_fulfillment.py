"""按订单站点验收的镜像交付流程测试。

覆盖题目列举的全部风险：两个站点共用账号、分片重复、摘要错配、客户回执乱序、
供应商收费已付、缓存设备封签破损，以及网络补片与设备补交同时发生时不得双重验收。
"""

import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay
from imagecourt.edge_transfer import record as record_edge_counter
from imagecourt.customer_delivery import provisional_bytes
from imagecourt.customer_fulfillment import (
    CustomerFulfillment,
    accept_site,
    commit_order,
    fulfillment_report,
    record_chunk_receipt,
    record_digest_ack,
    run,
)

DIGEST = "sha256:image-v1"
CHUNKS = [{"idx": i, "digest": f"sha256:chunk-{i}", "bytes": 100} for i in range(8)]
NORTH = "dc-north"
SOUTH = "dc-south"
ACCOUNT = "acct-shared-agents"


def new_db():
    return connect(":memory:")


def commit_story_order(db, oid="ORD-1", daily_credit=80):
    return commit_order(
        db,
        order_id=oid,
        account=ACCOUNT,
        digest=DIGEST,
        sites=[NORTH, SOUTH],
        window_start=1,
        window_end=5,
        grace_end=10,
        day_seconds=1,
        daily_credit=daily_credit,
        chunks=CHUNKS,
    )


def fill_north(db, oid="ORD-1", at=2, ack_at=3, accept_at=3):
    for i in range(8):
        record_chunk_receipt(
            db, receipt_id=f"{oid}-n-rcpt-{i}", order_id=oid, site=NORTH,
            chunk_idx=i, at=at + (i % 2))
    record_digest_ack(db, ack_id=f"{oid}-n-ack", order_id=oid, site=NORTH,
                      digest=DIGEST, at=ack_at)
    return accept_site(db, order_id=oid, site=NORTH, at=accept_at)


def fill_south_prefix(db, oid="ORD-1", upto=5, at=4):
    """Customer can prove only the contiguous prefix 0..upto."""
    for i in range(upto, -1, -1):  # deliberately reverse insertion order
        record_chunk_receipt(
            db, receipt_id=f"{oid}-s-rcpt-{i}", order_id=oid, site=SOUTH,
            chunk_idx=i, at=at)


def inflate_edge_tally(db, oid="ORD-1"):
    """Edge claims the whole package plus a middle segment sent twice."""
    for i in range(8):
        run(db, {"op": "edge_send", "event_id": f"{oid}-ea-{i}", "order_id": oid,
                 "digest": DIGEST, "account": ACCOUNT, "node_id": "pop-a",
                 "chunk_idx": i, "bytes_sent": 100, "at": 4})
    for i in (3, 4):  # middle segment re-sent through another edge node
        run(db, {"op": "edge_send", "event_id": f"{oid}-eb-{i}", "order_id": oid,
                 "digest": DIGEST, "account": ACCOUNT, "node_id": "pop-b",
                 "chunk_idx": i, "bytes_sent": 100, "at": 4})


def build_story(oid="ORD-1", db=None):
    db = db or new_db()
    commit_story_order(db, oid)
    inflate_edge_tally(db, oid)
    fill_north(db, oid)
    fill_south_prefix(db, oid)
    run(db, {"op": "portal_mark", "order_id": oid, "site": SOUTH, "at": 5})
    return db


class SharedAccountSiteTests(unittest.TestCase):
    def test_two_sites_share_account_but_proof_is_site_bound(self):
        db = build_story()
        rep = fulfillment_report(db, "ORD-1")

        self.assertEqual(rep["account"], ACCOUNT)
        self.assertEqual(rep["accepted_sites"], [NORTH])
        self.assertTrue(rep["sites"][NORTH]["accepted"])
        self.assertFalse(rep["sites"][SOUTH]["accepted"])
        self.assertEqual(rep["sites"][SOUTH]["verified_chunks"], 6)
        self.assertEqual(rep["sites"][SOUTH]["missing_indexes"], [6, 7])
        # Portal falsely shows south accepted.
        self.assertIn(SOUTH, rep["portal_overstatement_sites"])
        self.assertTrue(rep["sites"][SOUTH]["portal_marked_accepted"])

    def test_receipts_for_one_site_never_satisfy_the_other(self):
        db = new_db()
        commit_story_order(db)
        fill_north(db)
        # North's eight receipts exist; south has none of its own.
        south = fulfillment_report(db, "ORD-1")["sites"][SOUTH]
        self.assertEqual(south["verified_chunks"], 0)
        self.assertEqual(south["missing_indexes"], list(range(8)))

        res = record_chunk_receipt(
            db, receipt_id="rogue", order_id="ORD-1", site="dc-third-floor",
            chunk_idx=0, at=2)
        self.assertEqual(res["decision"], "site_not_on_order")

    def test_late_receipt_cannot_move_between_sites(self):
        db = build_story()
        # A late receipt labelled north only strengthens north, never south.
        res = record_chunk_receipt(
            db, receipt_id="late-n-extra", order_id="ORD-1", site=NORTH,
            chunk_idx=6, at=20)
        self.assertEqual(res["decision"], "chunk_receipt_deduplicated")
        rep = fulfillment_report(db, "ORD-1", at=20)
        self.assertEqual(rep["sites"][SOUTH]["missing_indexes"], [6, 7])
        self.assertEqual(rep["sites"][NORTH]["delivered_at"], 3)


class EdgeTallyTrapTests(unittest.TestCase):
    def test_naive_sum_double_counts_retried_middle_segment(self):
        db = build_story()
        # 8 full-package records + 2 duplicate middle-segment sends = 1000.
        self.assertEqual(naive := provisional_bytes(db, DIGEST, ACCOUNT), 1000)
        rep = fulfillment_report(db, "ORD-1")
        self.assertEqual(rep["edge"]["claimed_bytes_sum"], 1000)
        self.assertEqual(rep["edge"]["naive_provisional_bytes"], 1000)
        # Customer proof covers only 600 of 800 bytes at south.
        self.assertEqual(rep["sites"][SOUTH]["verified_bytes"], 600)
        self.assertEqual(rep["sites"][SOUTH]["missing_bytes"], 200)

    def test_legacy_provisional_increment_still_simple_sum(self):
        # Mirrors the isolated enhanced test: one send record adds 16.
        db = new_db()
        record_edge_counter(db, "e1", "sha256:artifact", "customer-x", 16)
        self.assertEqual(provisional_bytes(db, "sha256:artifact", "customer-x"), 16)

    def test_more_edge_records_never_accept_site(self):
        db = build_story()
        for k in range(5):
            run(db, {"op": "edge_send", "event_id": f"desperate-{k}",
                     "order_id": "ORD-1", "digest": DIGEST, "account": ACCOUNT,
                     "node_id": f"pop-{k}", "bytes_sent": 800, "at": 11})
        res = run(db, {"op": "complete_from_edge", "order_id": "ORD-1",
                       "site": SOUTH, "event_id": "desperate-final", "at": 11,
                       "digest": DIGEST, "account": ACCOUNT, "bytes_sent": 800})
        self.assertEqual(res["decision"], "edge_record_not_proof")
        self.assertEqual(res["missing_chunks"], [6, 7])
        count = db.execute(
            "SELECT COUNT(*) c FROM cf_acceptances WHERE site=?", (SOUTH,)
        ).fetchone()["c"]
        self.assertEqual(count, 0)


class ReceiptSemanticsTests(unittest.TestCase):
    def test_duplicate_receipts_count_each_chunk_once(self):
        db = new_db()
        commit_order(db, order_id="DUP", account="a", digest=DIGEST,
                     sites=[NORTH], window_start=0, window_end=5,
                     day_seconds=1, chunks=4)
        first = record_chunk_receipt(
            db, receipt_id="r0", order_id="DUP", site=NORTH, chunk_idx=0, at=1)
        again_same_id = record_chunk_receipt(
            db, receipt_id="r0", order_id="DUP", site=NORTH, chunk_idx=0, at=1)
        retry_new_id = record_chunk_receipt(
            db, receipt_id="r0-retry", order_id="DUP", site=NORTH,
            chunk_idx=0, at=1)
        self.assertEqual(first["decision"], "chunk_receipt_recorded")
        self.assertEqual(again_same_id["decision"], "reused")
        self.assertEqual(retry_new_id["decision"], "chunk_receipt_deduplicated")
        rep = fulfillment_report(db, "DUP")
        self.assertEqual(rep["sites"][NORTH]["verified_chunks"], 1)

    def test_out_of_order_receipts_still_yield_max_receipt_time(self):
        db = new_db()
        commit_order(db, order_id="OOO", account="a", digest=DIGEST,
                     sites=[NORTH], window_start=0, window_end=9,
                     day_seconds=1, chunks=4)
        # Insertion order and receipt times are both scrambled.
        for idx, at in [(2, 2), (0, 4), (3, 3), (1, 5)]:
            record_chunk_receipt(
                db, receipt_id=f"o-{idx}", order_id="OOO", site=NORTH,
                chunk_idx=idx, at=at)
        site = fulfillment_report(db, "OOO")["sites"][NORTH]
        self.assertEqual(site["verified_indexes"], [0, 1, 2, 3])
        self.assertEqual(site["proof_ready_at"], 5)
        record_digest_ack(db, ack_id="o-ack", order_id="OOO", site=NORTH,
                          digest=DIGEST, at=5)
        res = accept_site(db, order_id="OOO", site=NORTH, at=6)
        self.assertEqual(res["decision"], "site_accepted")
        self.assertEqual(res["delivered_at"], 5)


class DigestMismatchTests(unittest.TestCase):
    def test_wrong_chunk_digest_is_evidence_but_not_verified(self):
        db = new_db()
        commit_order(db, order_id="MM", account="a", digest=DIGEST,
                     sites=[NORTH], window_start=0, window_end=5,
                     day_seconds=1,
                     chunks=[{"idx": 0, "digest": "h0", "bytes": 10},
                             {"idx": 1, "digest": "h1", "bytes": 10}])
        ok = record_chunk_receipt(db, receipt_id="c0", order_id="MM",
                                  site=NORTH, chunk_idx=0,
                                  chunk_digest="h0", at=1)
        bad = record_chunk_receipt(db, receipt_id="c1bad", order_id="MM",
                                   site=NORTH, chunk_idx=1,
                                   chunk_digest="sha256:evil", at=1)
        self.assertEqual(ok["decision"], "chunk_receipt_recorded")
        self.assertEqual(bad["decision"], "chunk_digest_mismatch")
        site = fulfillment_report(db, "MM")["sites"][NORTH]
        self.assertEqual(site["verified_indexes"], [0])
        self.assertEqual(site["missing_indexes"], [1])

        fixed = record_chunk_receipt(db, receipt_id="c1ok", order_id="MM",
                                     site=NORTH, chunk_idx=1,
                                     chunk_digest="h1", at=2)
        self.assertEqual(fixed["decision"], "chunk_receipt_recorded")

    def test_wrong_whole_digest_ack_blocks_acceptance(self):
        db = new_db()
        commit_order(db, order_id="MA", account="a", digest=DIGEST,
                     sites=[NORTH], window_start=0, window_end=5,
                     day_seconds=1, chunks=2)
        for i in range(2):
            record_chunk_receipt(db, receipt_id=f"m-{i}", order_id="MA",
                                 site=NORTH, chunk_idx=i, at=1)
        bad_ack = record_digest_ack(db, ack_id="bad-ack", order_id="MA",
                                    site=NORTH, digest="sha256:other", at=2)
        self.assertEqual(bad_ack["decision"], "digest_mismatch")
        blocked = accept_site(db, order_id="MA", site=NORTH, at=2)
        self.assertEqual(blocked["decision"], "digest_mismatch")

        record_digest_ack(db, ack_id="good-ack", order_id="MA", site=NORTH,
                          digest=DIGEST, at=3)
        accepted = accept_site(db, order_id="MA", site=NORTH, at=3)
        self.assertEqual(accepted["decision"], "site_accepted")

    def test_device_with_wrong_digest_cannot_verify(self):
        db = new_db()
        commit_story_order(db, "DW")
        run(db, {"op": "register_device", "device_id": "dev-w",
                 "order_id": "DW", "digest": "sha256:preloaded-wrong"})
        res = run(db, {"op": "verify_device", "verification_id": "vw",
                       "device_id": "dev-w", "order_id": "DW",
                       "site": SOUTH, "at": 8})
        self.assertEqual(res["decision"], "device_digest_mismatch")


class NetworkGraceCureTests(unittest.TestCase):
    def test_network_patch_within_grace_settles_daily_relief(self):
        db = build_story("NET")
        opened = run(db, {"op": "open_remediation", "remediation_id": "rm-n",
                          "order_id": "NET", "site": SOUTH,
                          "method": "network_patch", "at": 6})
        self.assertEqual(opened["decision"], "remediation_opened")

        # Tail chunks arrive out of insertion order; still inside grace_end=10.
        record_chunk_receipt(db, receipt_id="net-7", order_id="NET",
                             site=SOUTH, chunk_idx=7, at=9)
        record_chunk_receipt(db, receipt_id="net-6", order_id="NET",
                             site=SOUTH, chunk_idx=6, at=8)
        record_digest_ack(db, ack_id="net-ack", order_id="NET", site=SOUTH,
                          digest=DIGEST, at=9)
        res = accept_site(db, order_id="NET", site=SOUTH, at=9,
                          remediation_id="rm-n")
        self.assertEqual(res["decision"], "site_accepted")
        self.assertFalse(res["on_time"])
        # chunk6 3 late units + chunk7 4 late units -> 80*(300+400)/800 = 70.
        self.assertEqual(res["credit"], 70)

        rep = fulfillment_report(db, "NET")
        self.assertEqual(rep["status"], "accepted")
        self.assertEqual(rep["accepted_sites"], [NORTH, SOUTH])
        self.assertEqual(rep["credit"]["granted_total"], 70)
        self.assertEqual(rep["credit"]["calculated_total"], 70)
        north = rep["sites"][NORTH]
        self.assertEqual((north["accepted_at"], north["delivered_at"]), (3, 3))

        card = next(c for c in rep["scorecard"] if c["method"] == "network_patch")
        self.assertTrue(card["effective"])
        self.assertEqual(card["customer_available_at"], 9)
        self.assertEqual(card["network_bytes_required_for_plan"], 200)
        self.assertEqual(card["network_bytes_delivered_cure"], 200)
        self.assertEqual(card["shipping_cost"], 0)
        self.assertEqual(card["credit_linked"], 70)


def device_world(oid="DEV", custody=True):
    db = build_story(oid)
    run(db, {"op": "open_remediation", "remediation_id": "rm-d",
             "order_id": oid, "site": SOUTH, "method": "cache_device",
             "at": 6, "device_id": "dev-1"})
    run(db, {"op": "register_device", "device_id": "dev-1",
             "order_id": oid, "digest": DIGEST, "at": 6})
    run(db, {"op": "ship_device", "shipment_id": "ship-out",
             "device_id": "dev-1", "order_id": oid, "site": SOUTH,
             "at": 6, "cost": 300, "via": ["WH-THIRD-PARTY"]})
    run(db, {"op": "report_seal", "seal_event_id": "seal-1",
             "device_id": "dev-1", "seal_id": "tape-9",
             "status": "intact", "at": 6})
    if custody:
        run(db, {"op": "custody_checkpoint", "checkpoint_id": "cp-1",
                 "device_id": "dev-1", "code": "WH-THIRD-PARTY",
                 "party": "ThirdParty Warehouse Ltd",
                 "kind": "third_party_warehouse", "at": 7,
                 "seal_intact": True, "customer_key_only": True,
                 "proof_ref": "vault-camera/seat-seal-cert-1"})
    return db


class CacheDeviceTests(unittest.TestCase):
    def test_device_requires_warehouse_seal_and_customer_only_key_proof(self):
        db = device_world("DC-PROOF", custody=False)
        res = run(db, {"op": "verify_device", "verification_id": "v-missing",
                       "device_id": "dev-1", "order_id": "DC-PROOF",
                       "site": SOUTH, "at": 8, "verified_indexes": [6, 7]})
        self.assertEqual(res["decision"], "custody_proof_missing")

        run(db, {"op": "custody_checkpoint", "checkpoint_id": "cp-bad-key",
                 "device_id": "dev-1", "code": "WH-THIRD-PARTY", "at": 7,
                 "seal_intact": True, "customer_key_only": False,
                 "proof_ref": "shared-key-escrow"})
        # A second verification id still fails, now on key exclusivity.
        res2 = run(db, {"op": "verify_device", "verification_id": "v-key",
                        "device_id": "dev-1", "order_id": "DC-PROOF",
                        "site": SOUTH, "at": 8, "verified_indexes": [6, 7]})
        self.assertEqual(res2["decision"], "device_key_not_customer_only")

    def test_warehouse_checkpoint_without_explicit_proof_fails_closed(self):
        db = device_world("DC-NOFLAGS", custody=False)
        # Checkpoint exists but does not actually assert seal/key/proof facts.
        run(db, {"op": "custody_checkpoint", "checkpoint_id": "cp-empty",
                 "device_id": "dev-1", "code": "WH-THIRD-PARTY",
                 "party": "ThirdParty Warehouse Ltd", "at": 7})
        res = run(db, {"op": "verify_device", "verification_id": "v-empty",
                       "device_id": "dev-1", "order_id": "DC-NOFLAGS",
                       "site": SOUTH, "at": 8})
        self.assertEqual(res["decision"], "custody_proof_missing")

    def test_intact_device_verifies_and_jointly_accepts_with_platform_freight(self):
        db = device_world("DEV")
        v = run(db, {"op": "verify_device", "verification_id": "v-1",
                     "device_id": "dev-1", "order_id": "DEV",
                     "site": SOUTH, "at": 8, "verified_indexes": [6, 7]})
        self.assertEqual(v["decision"], "device_verified")
        self.assertEqual(v["derived_receipts"], [6, 7])

        j = run(db, {"op": "joint_accept", "joint_id": "joint-1",
                     "order_id": "DEV", "device_id": "dev-1",
                     "verification_id": "v-1", "at": 8,
                     "remediation_id": "rm-d"})
        self.assertEqual(j["decision"], "jointly_accepted")
        self.assertEqual(j["accepted_now"], [SOUTH])

        rep = fulfillment_report(db, "DEV")
        self.assertTrue(rep["all_accepted"])
        self.assertEqual(rep["joint_acceptances"], ["joint-1"])
        # Both tail chunks arrive at day 8 -> 3 late units each -> 60.
        self.assertEqual(rep["credit"]["granted_total"], 60)
        self.assertEqual(rep["costs"]["shipping_platform"], 300)
        self.assertEqual(rep["costs"]["shipping_customer"], 0)

        card = next(c for c in rep["scorecard"] if c["method"] == "cache_device")
        self.assertTrue(card["effective"])
        self.assertEqual(card["customer_available_at"], 8)
        self.assertEqual(card["network_bytes_required_for_plan"], 0)
        self.assertEqual(card["network_bytes_delivered_cure"], 0)
        self.assertEqual(card["device_bytes_delivered"], 200)
        self.assertEqual(card["shipping_cost"], 300)

        # North's original sign-off is preserved, not re-dated to day 8.
        north = rep["sites"][NORTH]
        self.assertEqual(north["accepted_at"], 3)
        self.assertEqual(north["delivered_at"], 3)
        self.assertTrue(north["on_time"])


class BrokenSealConcurrentCureTests(unittest.TestCase):
    def test_broken_seal_return_and_network_patch_accept_exactly_once(self):
        db = build_story("CONC")
        run(db, {"op": "open_remediation", "remediation_id": "rm-net",
                 "order_id": "CONC", "site": SOUTH,
                 "method": "network_patch", "at": 6})
        run(db, {"op": "open_remediation", "remediation_id": "rm-dev",
                 "order_id": "CONC", "site": SOUTH,
                 "method": "cache_device", "at": 6, "device_id": "dev-c"})
        run(db, {"op": "register_device", "device_id": "dev-c",
                 "order_id": "CONC", "digest": DIGEST})
        run(db, {"op": "ship_device", "shipment_id": "ship-c-out",
                 "device_id": "dev-c", "order_id": "CONC", "at": 6,
                 "cost": 300, "via": ["WH-C"]})
        broken = run(db, {"op": "report_seal", "seal_event_id": "seal-c",
                          "device_id": "dev-c", "seal_id": "tape-c",
                          "status": "broken", "at": 7})
        self.assertEqual(broken["decision"], "seal_broken_recorded")
        run(db, {"op": "custody_checkpoint", "checkpoint_id": "cp-c",
                 "device_id": "dev-c", "code": "WH-C", "at": 7,
                 "seal_intact": False, "customer_key_only": True,
                 "proof_ref": "broken-seal-photo"})

        verified = run(db, {"op": "verify_device", "verification_id": "v-c",
                            "device_id": "dev-c", "order_id": "CONC",
                            "site": SOUTH, "at": 8})
        self.assertEqual(verified["decision"], "device_seal_broken")

        returned = run(db, {"op": "return_device", "shipment_id": "ship-c-ret",
                            "device_id": "dev-c", "order_id": "CONC",
                            "at": 9, "cost": 120})
        self.assertEqual(returned["decision"], "device_return_recorded")
        self.assertEqual(returned["billed_to"], "platform")

        # Network patch lands at the same time as the failed device visit.
        for i in (6, 7):
            record_chunk_receipt(db, receipt_id=f"conc-net-{i}",
                                  order_id="CONC", site=SOUTH,
                                  chunk_idx=i, at=8)
        record_digest_ack(db, ack_id="conc-ack", order_id="CONC",
                          site=SOUTH, digest=DIGEST, at=8)
        accepted = accept_site(db, order_id="CONC", site=SOUTH, at=8,
                               remediation_id="rm-net")
        self.assertEqual(accepted["decision"], "site_accepted")
        self.assertEqual(accepted["credit"], 60)

        # Device/joint route must not create a second acceptance.
        joint = run(db, {"op": "joint_accept", "order_id": "CONC",
                         "device_id": "dev-c", "verification_id": "v-c",
                         "at": 9})
        self.assertEqual(joint["decision"], "device_seal_broken")
        again = accept_site(db, order_id="CONC", site=SOUTH, at=9)
        self.assertEqual(again["decision"], "site_already_accepted")

        acc_rows = db.execute(
            "SELECT COUNT(*) c FROM cf_acceptances WHERE order_id='CONC'"
        ).fetchone()["c"]
        south_rows = db.execute(
            "SELECT COUNT(*) c FROM cf_acceptances WHERE order_id='CONC' "
            "AND site=?", (SOUTH,)).fetchone()["c"]
        grant_rows = db.execute(
            "SELECT COUNT(*) c FROM cf_credit_grants WHERE order_id='CONC' "
            "AND site=?", (SOUTH,)).fetchone()["c"]
        self.assertEqual(acc_rows, 2)       # one per site, never more
        self.assertEqual(south_rows, 1)
        self.assertEqual(grant_rows, 1)

        rep = fulfillment_report(db, "CONC")
        self.assertEqual(rep["status"], "accepted")
        self.assertEqual(rep["credit"]["granted_total"], 60)
        # Outbound + return freight both retained and borne by platform.
        self.assertEqual(rep["costs"]["shipping_platform"], 420)
        cards = {c["method"]: c for c in rep["scorecard"]}
        self.assertTrue(cards["network_patch"]["effective"])
        self.assertEqual(cards["network_patch"]["status"], "effective")
        self.assertFalse(cards["cache_device"]["effective"])
        self.assertEqual(cards["cache_device"]["status"], "failed")
        self.assertEqual(cards["cache_device"]["shipping_cost"], 420)

    def test_two_successful_cures_still_accept_once(self):
        db = build_story("BOTH-OK")
        run(db, {"op": "open_remediation", "remediation_id": "rn2",
                 "order_id": "BOTH-OK", "site": SOUTH,
                 "method": "network_patch", "at": 6})
        run(db, {"op": "open_remediation", "remediation_id": "rd2",
                 "order_id": "BOTH-OK", "site": SOUTH,
                 "method": "cache_device", "at": 6, "device_id": "dev-2"})
        run(db, {"op": "register_device", "device_id": "dev-2",
                 "order_id": "BOTH-OK", "digest": DIGEST})
        run(db, {"op": "ship_device", "shipment_id": "sh2",
                 "device_id": "dev-2", "cost": 250, "via": []})
        # Network receipts arrive first.
        for i in (6, 7):
            record_chunk_receipt(db, receipt_id=f"both-{i}",
                                 order_id="BOTH-OK", site=SOUTH,
                                 chunk_idx=i, at=8)
        record_digest_ack(db, ack_id="both-ack", order_id="BOTH-OK",
                          site=SOUTH, digest=DIGEST, at=8)
        self.assertEqual(
            accept_site(db, order_id="BOTH-OK", site=SOUTH, at=8,
                        remediation_id="rn2")["decision"], "site_accepted")
        # Device also verifies the same bytes; derived receipts are duplicates.
        v = run(db, {"op": "verify_device", "verification_id": "v2",
                     "device_id": "dev-2", "order_id": "BOTH-OK",
                     "site": SOUTH, "at": 8, "all_chunks": True})
        self.assertEqual(v["decision"], "device_verified")
        self.assertEqual(v["derived_receipts"], [])
        joint = run(db, {"op": "joint_accept", "order_id": "BOTH-OK",
                         "device_id": "dev-2", "verification_id": "v2",
                         "at": 8, "remediation_id": "rd2"})
        self.assertEqual(joint["decision"], "already_accepted")
        total = db.execute(
            "SELECT COUNT(*) c FROM cf_acceptances WHERE order_id='BOTH-OK'"
        ).fetchone()["c"]
        self.assertEqual(total, 2)
        grants = db.execute(
            "SELECT COUNT(*) c FROM cf_credit_grants WHERE order_id='BOTH-OK'"
        ).fetchone()["c"]
        self.assertEqual(grants, 1)


class ArrangementDifferenceTests(unittest.TestCase):
    def test_network_and_device_arrangements_settle_differently(self):
        net = build_story("ARR-N")
        run(net, {"op": "open_remediation", "remediation_id": "rn",
                  "order_id": "ARR-N", "site": SOUTH,
                  "method": "network_patch", "at": 6})
        record_chunk_receipt(net, receipt_id="a6", order_id="ARR-N",
                             site=SOUTH, chunk_idx=6, at=8)
        record_chunk_receipt(net, receipt_id="a7", order_id="ARR-N",
                             site=SOUTH, chunk_idx=7, at=9)
        record_digest_ack(net, ack_id="aa", order_id="ARR-N",
                          site=SOUTH, digest=DIGEST, at=9)
        accept_site(net, order_id="ARR-N", site=SOUTH, at=9,
                    remediation_id="rn")
        net_card = fulfillment_report(net, "ARR-N")["scorecard"][0]

        dev = device_world("ARR-D")
        run(dev, {"op": "verify_device", "verification_id": "av",
                  "device_id": "dev-1", "order_id": "ARR-D",
                  "site": SOUTH, "at": 8, "verified_indexes": [6, 7]})
        run(dev, {"op": "joint_accept", "order_id": "ARR-D",
                  "device_id": "dev-1", "verification_id": "av", "at": 8,
                  "remediation_id": "rm-d"})
        dev_card = next(c for c in fulfillment_report(dev, "ARR-D")["scorecard"]
                        if c["method"] == "cache_device")

        self.assertEqual(net_card["customer_available_at"], 9)
        self.assertEqual(dev_card["customer_available_at"], 8)
        self.assertEqual(net_card["shipping_cost"], 0)
        self.assertEqual(dev_card["shipping_cost"], 300)
        self.assertEqual(net_card["network_bytes_required_for_plan"], 200)
        self.assertEqual(dev_card["network_bytes_required_for_plan"], 0)
        self.assertEqual(net_card["credit_linked"], 70)
        self.assertEqual(dev_card["credit_linked"], 60)


class VendorChargeTests(unittest.TestCase):
    def test_original_charge_retained_through_handoff_rename_and_payment(self):
        db = build_story("VND")
        run(db, {"op": "rename_handoff", "node_id": "hnd-east",
                 "name": "CDN-East/Handoff-A", "at": 1})
        recorded = run(db, {"op": "record_vendor_charge", "charge_id": "chg-1",
                            "vendor": "CDN Vendor", "node_id": "hnd-east",
                            "handoff_name": "CDN-East/Handoff-A",
                            "order_id": "VND", "digest": DIGEST,
                            "amount": 12345, "currency": "CNY", "at": 6})
        self.assertEqual(recorded["decision"], "vendor_charge_recorded")

        # Vendor renames the handoff point after the original invoice.
        run(db, {"op": "rename_handoff", "node_id": "hnd-east",
                 "name": "CDN-East/EdgePoint-Renamed", "at": 8})
        conflict = run(db, {"op": "record_vendor_charge", "charge_id": "chg-1",
                            "vendor": "CDN Vendor", "node_id": "hnd-east",
                            "handoff_name": "CDN-East/Handoff-A",
                            "order_id": "VND", "amount": 99999, "at": 6})
        self.assertEqual(conflict["decision"], "charge_identity_conflict")

        paid = run(db, {"op": "pay_vendor_charge", "charge_id": "chg-1",
                        "paid_at": 9})
        self.assertEqual(paid["decision"], "charge_paid")
        twice = run(db, {"op": "pay_vendor_charge", "charge_id": "chg-1",
                         "paid_at": 10})
        self.assertEqual(twice["decision"], "charge_already_paid")

        rep = fulfillment_report(db, "VND")
        self.assertEqual(rep["costs"]["vendor_charges_total"], 12345)
        self.assertEqual(rep["costs"]["vendor_charges_paid"], 12345)
        self.assertTrue(rep["costs"]["vendor_all_paid"])
        charge = rep["vendor_charges"][0]
        self.assertEqual(charge["status"], "paid")
        self.assertEqual(charge["paid_at"], 9)
        # Original handoff name and amount survive the rename.
        self.assertEqual(charge["handoff_name_original"], "CDN-East/Handoff-A")
        self.assertEqual(charge["amount"], 12345)
        current = db.execute("SELECT current_name FROM cf_handoffs WHERE node_id='hnd-east'"
                             ).fetchone()["current_name"]
        self.assertEqual(current, "CDN-East/EdgePoint-Renamed")
        aliases = [r["name"] for r in db.execute(
            "SELECT name FROM cf_handoff_aliases WHERE node_id='hnd-east'")]
        self.assertIn("CDN-East/Handoff-A", aliases)
        self.assertIn("CDN-East/EdgePoint-Renamed", aliases)


class ShortfallCorrectionTests(unittest.TestCase):
    def test_signed_delivery_time_is_immutable_and_correction_recomputes(self):
        db = new_db()
        commit_order(db, order_id="FIX", account="a", digest=DIGEST,
                     sites=[SOUTH], window_start=1, window_end=5,
                     grace_end=10, day_seconds=1, daily_credit=80, chunks=CHUNKS)
        # 0..5 on time at day 4, 6/7 late at day 8 -> credit 60.
        fill_south_prefix(db, "FIX")
        record_chunk_receipt(db, receipt_id="fix-6", order_id="FIX",
                             site=SOUTH, chunk_idx=6, at=8)
        record_chunk_receipt(db, receipt_id="fix-7", order_id="FIX",
                             site=SOUTH, chunk_idx=7, at=8)
        record_digest_ack(db, ack_id="fix-ack", order_id="FIX",
                          site=SOUTH, digest=DIGEST, at=8)
        accepted = accept_site(db, order_id="FIX", site=SOUTH, at=8)
        self.assertEqual((accepted["delivered_at"], accepted["credit"]), (8, 60))

        # Audit after sign-off finds chunk 3 was incomplete/corrupt.
        short = run(db, {"op": "report_shortfall", "correction_id": "corr-1",
                         "order_id": "FIX", "site": SOUTH, "at": 10,
                         "missing_indexes": [3],
                         "invalidate_receipt_id": "FIX-s-rcpt-3"})
        self.assertEqual(short["decision"],
                         "shortfall_recorded_breach_makeup_required")
        self.assertTrue(short["delivery_time_unchanged"])

        before = db.execute(
            "SELECT delivered_at, accepted_at FROM cf_acceptances "
            "WHERE order_id='FIX' AND site=?", (SOUTH,)).fetchone()
        self.assertEqual((before["delivered_at"], before["accepted_at"]), (8, 8))

        # Any attempt to backdate the old delivery into the window is refused.
        revise = run(db, {"op": "revise_delivery_time", "order_id": "FIX",
                          "site": SOUTH, "new_delivered_at": 4})
        self.assertEqual(revise["decision"], "delivery_time_immutable")
        self.assertEqual(revise["delivered_at"], 8)
        after = db.execute(
            "SELECT delivered_at FROM cf_acceptances WHERE order_id='FIX' "
            "AND site=?", (SOUTH,)).fetchone()
        self.assertEqual(after["delivered_at"], 8)

        rep_during = fulfillment_report(db, "FIX")
        site_during = rep_during["sites"][SOUTH]
        self.assertTrue(site_during["accepted"])  # sign-off never withdrawn
        self.assertEqual(site_during["status"],
                         "accepted_with_open_breach_correction")
        self.assertEqual(site_during["missing_indexes"], [3])
        self.assertEqual(site_during["open_corrections"], ["corr-1"])

        # Breach makeup: a fresh customer receipt for chunk 3 at day 11.
        makeup = record_chunk_receipt(
            db, receipt_id="fix-3-makeup", order_id="FIX", site=SOUTH,
            chunk_idx=3, chunk_digest="sha256:chunk-3", at=11,
            via="network-makeup")
        self.assertEqual(makeup["decision"], "chunk_receipt_recorded")
        calculated = run(db, {"op": "calculate_credit", "order_id": "FIX",
                              "site": SOUTH})
        # chunk3 now 6 late units instead of 3 -> extra 30 relief.
        self.assertEqual(calculated, 120)
        run(db, {"op": "grant_credit", "grant_id": "corr-1-credit",
                 "order_id": "FIX", "site": SOUTH, "amount": 60, "at": 11,
                 "reason": "post_acceptance_shortfall_correction",
                 "correction_id": "corr-1"})
        rep_after = fulfillment_report(db, "FIX")
        self.assertEqual(rep_after["sites"][SOUTH]["status"], "accepted_corrected")
        self.assertEqual(rep_after["sites"][SOUTH]["open_corrections"], [])
        self.assertEqual(rep_after["credit"]["granted_total"], 120)
        self.assertEqual(rep_after["credit"]["calculated_total"], 120)
        # Still exactly one immutable acceptance row.
        rows = db.execute(
            "SELECT COUNT(*) c FROM cf_acceptances WHERE order_id='FIX'"
        ).fetchone()["c"]
        self.assertEqual(rows, 1)


class GraceExhaustedTests(unittest.TestCase):
    def test_after_grace_a_new_cdn_record_cannot_complete_site(self):
        db = build_story("LATE")
        rep = fulfillment_report(db, "LATE", at=11)
        self.assertTrue(rep["grace_exhausted"])
        self.assertEqual(rep["status"], "breach")
        self.assertEqual(rep["sites"][SOUTH]["status"],
                         "grace_exhausted_breach")

        edge_only = run(db, {"op": "complete_from_edge", "order_id": "LATE",
                             "site": SOUTH, "event_id": "one-more-cdn-send",
                             "digest": DIGEST, "account": ACCOUNT,
                             "bytes_sent": 800, "at": 11})
        self.assertEqual(edge_only["decision"], "edge_record_not_proof")
        self.assertEqual(edge_only["missing_chunks"], [6, 7])
        still = fulfillment_report(db, "LATE", at=12)
        self.assertFalse(still["sites"][SOUTH]["accepted"])
        self.assertEqual(still["sites"][SOUTH]["verified_chunks"], 6)


class AuditAndRobustnessTests(unittest.TestCase):
    def test_edge_cache_loss_keeps_customer_acceptance(self):
        db = build_story("CACHE-LOST")
        # Complete south over the network first.
        for i in (6, 7):
            record_chunk_receipt(db, receipt_id=f"cl-{i}",
                                 order_id="CACHE-LOST", site=SOUTH,
                                 chunk_idx=i, at=8)
        record_digest_ack(db, ack_id="cl-ack", order_id="CACHE-LOST",
                          site=SOUTH, digest=DIGEST, at=8)
        accept_site(db, order_id="CACHE-LOST", site=SOUTH, at=8)
        before_edge = provisional_bytes(db, DIGEST, ACCOUNT)
        self.assertGreater(before_edge, 0)

        lost = run(db, {"op": "lose_edge_cache", "order_id": "CACHE-LOST"})
        self.assertEqual(lost["decision"], "edge_cache_lost")
        self.assertTrue(lost["customer_proof_retained"])
        self.assertEqual(provisional_bytes(db, DIGEST, ACCOUNT), 0)

        rep = fulfillment_report(db, "CACHE-LOST")
        self.assertTrue(rep["all_accepted"])
        self.assertEqual(rep["accepted_sites"], [NORTH, SOUTH])
        self.assertEqual(rep["sites"][NORTH]["delivered_at"], 3)
        self.assertEqual(rep["sites"][SOUTH]["delivered_at"], 8)

    def test_works_with_plain_sqlite3_connection_and_id_style_ops(self):
        import sqlite3
        db = sqlite3.connect(":memory:")  # no store.connect row factory
        self.assertEqual(run(db, {
            "op": "create_order", "id": "PLAIN", "account": "a",
            "digest": "D", "sites": ["s1", "s2"], "window_start": 0,
            "window_end": 4, "grace_end": 8, "day_seconds": 1,
            "daily_credit": 10, "chunks": 2})["decision"], "order_committed")
        self.assertEqual(run(db, {
            "op": "receipt", "id": "rr0", "order_id": "PLAIN", "site": "s1",
            "chunk_index": 0, "at": 1})["decision"], "chunk_receipt_recorded")
        self.assertEqual(run(db, {
            "op": "receipt", "id": "rr1", "order_id": "PLAIN", "site": "s1",
            "chunk_index": 1, "at": 1})["decision"], "chunk_receipt_recorded")
        self.assertEqual(run(db, {
            "op": "ack", "id": "ka", "order_id": "PLAIN", "site": "s1",
            "digest": "D", "at": 2})["decision"], "digest_ack_recorded")
        self.assertEqual(run(db, {
            "op": "accept", "order_id": "PLAIN", "site": "s1",
            "at": 2})["decision"], "site_accepted")
        rep = run(db, {"op": "conclusion", "id": "PLAIN"})
        self.assertEqual(rep["decision"], "fulfillment_report")
        self.assertEqual(rep["accepted_sites"], ["s1"])

    def test_settlement_digest_is_deterministic(self):
        from imagecourt.customer_fulfillment import settlement_digest
        db = build_story("HASH")
        h1 = settlement_digest(db, "HASH")
        h2 = settlement_digest(db, "HASH")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        out = run(db, {"op": "settlement_hash", "id": "HASH"})
        self.assertEqual(out["decision"], "settlement_hash")
        self.assertEqual(out["sha256"], f"sha256:{h1}")


class DispatchFacadeAndReplayTests(unittest.TestCase):
    def test_run_dispatch_and_class_facade(self):
        db = new_db()
        svc = CustomerFulfillment(db)
        self.assertEqual(svc.run({
            "op": "commit_order", "order_id": "F1", "account": "a",
            "digest": "D", "sites": ["s"], "window_start": 0, "window_end": 2,
            "day_seconds": 1, "chunks": 1})["decision"], "order_committed")
        self.assertEqual(svc.chunk_receipt(
            {"receipt_id": "r", "order_id": "F1", "site": "s",
             "chunk_idx": 0, "at": 1})["decision"], "chunk_receipt_recorded")
        self.assertEqual(svc.digest_ack(
            ack_id="a", order_id="F1", site="s", digest="D", at=1)["decision"],
            "digest_ack_recorded")
        self.assertEqual(svc.accept_site(
            order_id="F1", site="s", at=1)["decision"], "site_accepted")
        rep = svc.fulfillment_report("F1")
        self.assertTrue(rep["all_accepted"])
        with self.assertRaises(ValueError):
            run(db, {"op": "not_a_real_op"})

    def test_store_execute_replays_to_identical_state(self):
        tmp = tempfile.TemporaryDirectory()
        path = str(Path(tmp.name) / "replay.sqlite")
        db = connect(path)
        events = [
            {"op": "commit_order", "order_id": "R1", "account": "a",
             "digest": "D", "sites": ["x", "y"], "window_start": 0,
             "window_end": 5, "grace_end": 9, "day_seconds": 1,
             "daily_credit": 40, "chunks": 4},
            {"op": "edge_send", "event_id": "e1", "order_id": "R1",
             "digest": "D", "account": "a", "bytes_sent": 40},
            {"op": "chunk_receipt", "receipt_id": "1", "order_id": "R1",
             "site": "x", "chunk_idx": 0, "at": 1},
            {"op": "chunk_receipt", "receipt_id": "2", "order_id": "R1",
             "site": "x", "chunk_idx": 1, "at": 1},
            {"op": "chunk_receipt", "receipt_id": "3", "order_id": "R1",
             "site": "x", "chunk_idx": 2, "at": 2},
            {"op": "chunk_receipt", "receipt_id": "4", "order_id": "R1",
             "site": "x", "chunk_idx": 3, "at": 2},
            {"op": "digest_ack", "ack_id": "a", "order_id": "R1",
             "site": "x", "digest": "D", "at": 2},
            {"op": "accept_site", "order_id": "R1", "site": "x", "at": 2},
            {"op": "report", "order_id": "R1"},
        ]
        for event in events:
            result = execute(db, "customer_fulfillment", event)
            self.assertNotEqual(result["decision"], "invalid_payload")
        db.close()
        verified = replay(path)
        self.assertTrue(verified["verified"], verified)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
