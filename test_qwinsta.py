#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests for qwinsta.

These exercise everything that does not need a live Windows host: the MS-TSTS
NDR response traversal (against real impacket structures), the state/type
mapping, argument normalisation, target parsing and table formatting.
"""

import argparse
import unittest

from impacket.dcerpc.v5 import tsts

import qwinsta


class TestStateMapping(unittest.TestCase):
    def test_known_states(self):
        self.assertEqual(qwinsta.STATE_SHORT[0], "Active")
        self.assertEqual(qwinsta.STATE_SHORT[4], "Disc")
        self.assertEqual(qwinsta.STATE_SHORT[6], "Listen")

    def test_session_state_label_fallback(self):
        s = qwinsta.Session(3, "x", 99)  # unmapped value
        self.assertEqual(s.state_label, "99")


class TestEnumTraversal(unittest.TestCase):
    """_iter_enum_result must walk a real RpcGetEnumResultEx response graph."""

    def _build_response(self, rows):
        resp = tsts.RpcGetEnumResultExResponse()
        items = []
        for sid, state, name in rows:
            si = tsts.SessionInfo_STRUCT()
            si["Level"] = 1
            si["SessionInfo"]["tag"] = 1
            lvl = si["SessionInfo"]["SessionEnum_Level1"]
            lvl["SessionId"] = sid
            lvl["State"] = state
            lvl["Name"] = name + "\x00"
            items.append(si)
        resp["ppSessionEnumResult"] = items
        resp["pEntries"] = len(rows)
        resp["ErrorCode"] = 0
        return resp

    def test_iterates_level1(self):
        rows = [(0, 4, "services"), (1, 1, "console"),
                (2, 0, "RDP-Tcp#0"), (65536, 6, "rdp-tcp")]
        resp = self._build_response(rows)
        self.assertEqual(list(qwinsta._iter_enum_result(resp)), rows)

    def test_empty(self):
        resp = self._build_response([])
        self.assertEqual(list(qwinsta._iter_enum_result(resp)), [])


class _FakePtr(object):
    """Mimics an impacket NDR pointer with a dict of accessible fields."""

    def __init__(self, fields):
        self._f = {} if fields is None else dict(fields)

    def __getitem__(self, key):
        return self._f[key]


class _FakeTS(object):
    """Stand-in for tsts.TermSrvSession returning a canned Ex response.

    ``flat=True`` reproduces the real impacket layout (union member flattened
    onto the pointer); ``flat=False`` exercises the 'Data' referent fallback.
    """

    def __init__(self, by_id, flat=True):
        self._by_id = by_id
        self._flat = flat

    def hRpcGetSessionInformationEx(self, sid):
        level1 = self._by_id[sid]
        if level1 is None:
            ptr = _FakePtr(None)
        elif self._flat:
            ptr = _FakePtr({"tag": 1, "LSM_SessionInfo_Level1": level1})
        else:
            ptr = _FakePtr({"Data": {"LSM_SessionInfo_Level1": level1}})
        return {"LSMSessionInfoExPtr": ptr}


class TestEnrichViaEx(unittest.TestCase):
    def _level1(self):
        return {
            "UserName": "Administrator\x00",
            "DomainName": "CORP\x00",
            "SessionName": "RDP-Tcp#0\x00",
            "SessionState": 0,
        }

    def test_reads_flat_layout(self):
        ts = _FakeTS({2: self._level1()}, flat=True)
        sess = qwinsta.Session(2, "Console", 1)  # stale name/state from enum
        got = qwinsta._enrich_via_ex(ts, sess, want_type=False, debug=False)
        self.assertTrue(got)
        self.assertEqual(sess.user, "Administrator")
        self.assertEqual(sess.domain, "CORP")
        self.assertEqual(sess.name, "RDP-Tcp#0")      # live name overrides enum's
        self.assertEqual(sess.state_label, "Active")  # state refreshed from Ex

    def test_reads_data_referent_fallback(self):
        ts = _FakeTS({2: self._level1()}, flat=False)
        sess = qwinsta.Session(2, "Console", 1)
        self.assertTrue(qwinsta._enrich_via_ex(ts, sess, want_type=False, debug=False))
        self.assertEqual(sess.user, "Administrator")

    def test_null_referent_returns_false(self):
        ts = _FakeTS({0: None})
        sess = qwinsta.Session(0, "Services", 4)
        self.assertFalse(qwinsta._enrich_via_ex(ts, sess, want_type=False, debug=False))
        self.assertEqual(sess.user, "")


class TestPrettyFormatting(unittest.TestCase):
    def _mk(self, sid, name, state, user=""):
        s = qwinsta.Session(sid, name, state)
        s.user = user
        return s

    def test_placeholders_and_states(self):
        sess = [self._mk(0, "Services", 4),
                self._mk(2, "", 4, "administrator"),
                self._mk(4, "Console", 1)]
        text = qwinsta.format_table_pretty(sess, color=False)
        self.assertIn("Disconnected", text)
        self.assertIn("Connected", text)
        self.assertNotIn("Disc ", text)           # no cryptic short code
        self.assertIn("administrator", text)
        # empty session name and empty user render as the placeholder.
        self.assertIn("| -", text.replace("│", "|"))

    def test_summary_signed_in(self):
        sess = [self._mk(2, "", 4, "administrator")]
        text = qwinsta.format_table_pretty(sess, color=False)
        self.assertIn("1 signed in: administrator (disconnected)", text)

    def test_summary_no_users(self):
        sess = [self._mk(0, "Services", 4), self._mk(3, "Console", 1)]
        text = qwinsta.format_table_pretty(sess, color=False)
        self.assertIn("no users signed in", text)

    def test_no_color_has_no_ansi(self):
        sess = [self._mk(2, "RDP-Tcp#0", 0, "administrator")]
        self.assertNotIn("\x1b[", qwinsta.format_table_pretty(sess, color=False))

    def test_color_wraps_active_state(self):
        sess = [self._mk(2, "RDP-Tcp#0", 0, "administrator")]
        text = qwinsta.format_table_pretty(sess, color=True)
        self.assertIn("\x1b[32m", text)  # green somewhere (Active state)


class TestTargetParsing(unittest.TestCase):
    def test_full(self):
        self.assertEqual(
            qwinsta.parse_target("CORP/admin:P@ss@10.0.0.5"),
            ("CORP", "admin", "P@ss", "10.0.0.5"),
        )

    def test_user_host(self):
        self.assertEqual(qwinsta.parse_target("admin@dc01"),
                         ("", "admin", "", "dc01"))

    def test_host_only(self):
        self.assertEqual(qwinsta.parse_target("10.0.0.5"),
                         ("", "", "", "10.0.0.5"))

    def test_domain_user_no_pass(self):
        self.assertEqual(qwinsta.parse_target("CORP/admin@host"),
                         ("CORP", "admin", "", "host"))


class TestConnectionResolution(unittest.TestCase):
    def _args(self, **kw):
        ns = argparse.Namespace(target=None, server=None, username=None,
                                password=None, domain="")
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_target_string(self):
        self.assertEqual(
            qwinsta.resolve_connection(self._args(target="CORP/admin:pw@10.0.0.5")),
            ("CORP", "admin", "pw", "10.0.0.5"))

    def test_server_flag_with_cred_flags(self):
        self.assertEqual(
            qwinsta.resolve_connection(
                self._args(server="10.0.0.5", username="admin", domain="CORP")),
            ("CORP", "admin", "", "10.0.0.5"))

    def test_server_flag_overrides_target_host(self):
        got = qwinsta.resolve_connection(
            self._args(target="admin@wrong", server="10.0.0.5"))
        self.assertEqual(got[1], "admin")
        self.assertEqual(got[3], "10.0.0.5")


class TestFormatting(unittest.TestCase):
    def _sessions(self):
        data = [(0, 4, "services", ""), (1, 1, "console", ""),
                (2, 0, "RDP-Tcp#0", "Administrator"), (65536, 6, "rdp-tcp", "")]
        out = []
        for sid, state, name, user in data:
            s = qwinsta.Session(sid, name, state)
            s.user = user
            out.append(s)
        out[2].is_current = True
        return out

    def test_header_present(self):
        text = qwinsta.format_table(self._sessions())
        self.assertIn("SESSIONNAME", text)
        self.assertIn("USERNAME", text)

    def test_no_header(self):
        text = qwinsta.format_table(self._sessions(), show_header=False)
        self.assertNotIn("SESSIONNAME", text)

    def test_current_marker_and_user(self):
        text = qwinsta.format_table(self._sessions())
        line = [l for l in text.splitlines() if "RDP-Tcp#0" in l][0]
        self.assertTrue(line.startswith(">"))
        self.assertIn("Administrator", line)
        self.assertIn("Active", line)

    def test_sorted_by_id(self):
        text = qwinsta.format_table(self._sessions(), show_header=False)
        ids_order = [l for l in text.splitlines()]
        self.assertTrue(ids_order[0].lstrip().startswith("services"))
        self.assertTrue(ids_order[-1].lstrip().startswith("rdp-tcp"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
