# tests/test_scan_parallel.py
"""Параллельный подбор (core/scan_parallel + StrategyScanner._probe_batch):
дорожки по памяти, сборка пачки, порты проб, правила, перепроверка."""

import socket
import unittest
from unittest import mock

from core import scan_parallel as sp


def meminfo(total_mb, avail_mb):
    return ("MemTotal:       %d kB\nMemFree: 1 kB\nMemAvailable:   %d kB\n"
            % (total_mb * 1024, avail_mb * 1024))


class TestSlots(unittest.TestCase):

    def test_memory_ceiling(self):
        self.assertEqual(sp.slots_for_memory(meminfo(128, 100)), 5)
        self.assertEqual(sp.slots_for_memory(meminfo(256, 200)), 10)
        self.assertEqual(sp.slots_for_memory(meminfo(512, 400)), 15)
        # Мало свободной — по свободной.
        self.assertEqual(sp.slots_for_memory(meminfo(512, 21)), 4)
        self.assertEqual(sp.slots_for_memory(meminfo(512, 10)), 1)
        self.assertEqual(sp.slots_for_memory(""), 1)
        # Старое ядро без MemAvailable — по MemFree.
        old = "MemTotal: %d kB\nMemFree: %d kB\n" % (512 * 1024, 100 * 1024)
        self.assertEqual(sp.slots_for_memory(old), 15)

    def test_marks_and_ports_distinct(self):
        marks = {sp.slot_mark(k) for k in range(sp.PAR_MAX)}
        self.assertEqual(len(marks), sp.PAR_MAX)
        self.assertTrue(all(m & sp.PAR_MASK == m and m for m in marks))
        ranges = [sp.slot_ports(k) for k in range(sp.PAR_MAX)]
        for (a, b), (c, d) in zip(ranges, ranges[1:]):
            self.assertLess(b, c)
        # Вне эфемерного диапазона Linux.
        self.assertLess(ranges[-1][1], 32768)
        self.assertEqual(sp.slot_filter(0),
                         "--filter-mark=0x01000000/0x0f000000")

    def test_enabled_and_limit(self):
        for v in ("auto", "on", "true", "5", 5):
            self.assertTrue(sp.enabled(v), v)
        for v in ("off", "", None, "1", "0", "нет"):
            self.assertFalse(sp.enabled(v), v)
        self.assertEqual(sp.limit("auto"), sp.PAR_MAX)
        self.assertEqual(sp.limit("4"), 4)
        self.assertEqual(sp.limit("99"), sp.PAR_MAX)


class TestCombine(unittest.TestCase):

    def test_profiles_get_slot_filter_and_globals_hoisted(self):
        a = ["--filter-tcp=443", "--hostlist=/tmp/h.txt",
             "--lua-desync=multisplit:pos=1"]
        b = ["--blob=g:@/bin/g.bin", "--filter-tcp=443",
             "--lua-desync=fake:blob=g", "--new", "--filter-tcp=80",
             "--lua-desync=fake:blob=g"]
        argv, packed, alone = sp.combine([a, b])
        self.assertEqual(packed, [0, 1])
        self.assertEqual(alone, [])
        self.assertEqual(argv[0], "--blob=g:@/bin/g.bin")
        self.assertEqual(argv.count("--new"), 2)
        f0, f1 = sp.slot_filter(0), sp.slot_filter(1)
        self.assertEqual(argv[1], f0)
        # У полного пресета фильтр дорожки — в каждом его профиле.
        self.assertEqual(argv.count(f1), 2)

    def test_conflicting_blob_and_empty_go_alone(self):
        a = ["--blob=g:@/a.bin", "--lua-desync=fake:blob=g"]
        b = ["--blob=g:@/b.bin", "--lua-desync=fake:blob=g"]
        c = []
        d = ["--blob=g:@/a.bin", "--lua-desync=fake:blob=g:repeats=2"]
        argv, packed, alone = sp.combine([a, b, c, d])
        self.assertEqual(packed, [0, 3])
        self.assertEqual(alone, [1, 2])
        self.assertEqual(argv.count("--blob=g:@/a.bin"), 1)
        # Дорожки — по номеру среди вошедших.
        self.assertIn(sp.slot_filter(1), argv)
        self.assertNotIn(sp.slot_filter(2), argv)


class TestPortBinding(unittest.TestCase):

    def test_bind_skips_busy_and_rotates_across_threads(self):
        import threading
        from core import probe_mark
        lo, hi = 45200, 45203
        busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy.bind(("0.0.0.0", lo))
        got = []
        try:
            def one():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probe_mark._bind_port(s, (lo, hi))
                got.append(s)
            for _ in range(2):
                t = threading.Thread(target=one)
                t.start()
                t.join()
            ports = [s.getsockname()[1] for s in got]
            self.assertEqual(ports, [lo + 1, lo + 2])
        finally:
            busy.close()
            for s in got:
                s.close()
            probe_mark._next_port.pop((lo, hi), None)

    def test_bind_rotates_in_range(self):
        from core import probe_mark
        lo, hi = 45100, 45103
        socks = []
        try:
            for _ in range(3):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socks.append(s)
                probe_mark._bind_port(s, (lo, hi))
            ports = [s.getsockname()[1] for s in socks]
            self.assertEqual(len(set(ports)), 3)
            self.assertTrue(all(lo <= p <= hi for p in ports))
        finally:
            for s in socks:
                s.close()
            probe_mark._next_port.pop((lo, hi), None)

    def test_marking_restores_ports(self):
        from core import probe_mark
        with mock.patch.object(probe_mark, "_install"):
            with probe_mark.marking(0x80000000, ports=(1, 2)):
                self.assertEqual(probe_mark._tls.ports, (1, 2))
            self.assertIsNone(probe_mark._tls.ports)


class TestFirewallSlots(unittest.TestCase):

    def test_ipt_rules_mark_slot_ports(self):
        from core.firewall import FirewallManager, _sandbox_slots
        fw = FirewallManager.__new__(FirewallManager)
        cmds = []
        fw._nfqueue_supported = lambda c: True
        fw._multiport_supported = lambda c: True
        fw._connbytes_supported = lambda c: True
        fw._ensure_named_chain = lambda *a: True
        fw._run_cmd = lambda cmd: cmds.append(cmd) or True
        p = {"queue": 301, "mark": "0x80000000", "desync": "0x40000000",
             "exclude": "0x20000000", "tcp": "443", "udp": "443",
             "tcp_out": 20, "tcp_in": 10, "udp_out": 5, "udp_in": 3,
             "slots": _sandbox_slots(2)}
        self.assertTrue(fw._apply_sandbox_ipt("iptables", p))
        marks = [c for c in cmds if "MARK" in c and "--set-xmark" in c
                 and "CONNMARK" not in c]
        self.assertEqual(len(marks), 8)     # 2 дорожки × tcp/udp × туда/обратно
        first = marks[0]
        self.assertIn("20000:20255", first)
        self.assertIn("0x1000000/0xf000000", first)
        # Метка дорожки — раньше постановки в очередь.
        idx_mark = cmds.index(first)
        idx_q = next(i for i, c in enumerate(cmds) if "NFQUEUE" in c)
        self.assertLess(idx_mark, idx_q)

    def test_no_slots_no_rules(self):
        from core.firewall import _sandbox_slots
        self.assertEqual(_sandbox_slots(0), [])
        self.assertEqual(len(_sandbox_slots(99)), sp.PAR_MAX)


class FakeEntry:
    def __init__(self, sid):
        self.section_id = sid
        self.name = sid
        self.source_file = "x"
        self.level = "basic"
        self.label = ""

    def get_args_list(self):
        return ["--lua-desync=" + self.section_id]


class TestBatch(unittest.TestCase):

    def _scanner(self):
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner()
        sc._target, sc._protocol = "example.com", "tcp"
        sc._parallel = 4
        sc._start_index = 0
        sc._sandbox = mock.Mock()
        sc._sandbox.start.return_value = True
        sc._sandbox.is_running.return_value = True
        sc._sandbox_mark = 0x80000000
        sc._isolated = True
        return sc

    def test_batch_runs_together_and_rechecks_findings(self):
        sc = self._scanner()
        entries = [FakeEntry("s%d" % i) for i in range(5)]
        good = {"s1", "s3"}

        def deep():
            from core import probe_mark
            k = (probe_mark._tls.ports[0] - sp.PORT_BASE) // sp.PORTS_PER_SLOT
            ok = entries[k].section_id in good
            return {"success": ok, "latency_ms": 10.0, "error": "" if ok
                    else "TLS_RESET", "http_code": 200, "kbps": 1.0,
                    "body_passed": ok, "success_rate": 1.0 if ok else 0.0,
                    "score": 1.0, "test_type": "x", "details": "",
                    "per_host": []}

        solo = mock.Mock(side_effect=lambda e, i: mock.Mock(
            success=e.section_id != "s3", raw_data={}, strategy_id=e.section_id))
        with mock.patch.object(sc, "_deep_probe", side_effect=deep), \
                mock.patch.object(sc, "_build_strategy_args",
                                  side_effect=lambda e: e.get_args_list()), \
                mock.patch.object(sc, "_ensure_scan_rules", return_value=True), \
                mock.patch.object(sc, "_get_stabilization_delay",
                                  return_value=0), \
                mock.patch.object(sc, "_meminfo",
                                  return_value=meminfo(512, 400)), \
                mock.patch.object(sc, "_probe_one_strategy", solo), \
                mock.patch("core.probe_mark._install"):
            out, end = sc._probe_batch(entries, 0)
        self.assertEqual(end, 4)
        self.assertEqual(sorted(out), [0, 1, 2, 3])
        # Один nfqws2 на пачку из 4.
        sc._sandbox.start.assert_called_once()
        argv = sc._sandbox.start.call_args[0][0]
        self.assertEqual(argv.count("--new"), 3)
        # Находки — перепроверены по одной: s3 в одиночку не прошла.
        self.assertEqual(solo.call_count, 2)
        self.assertTrue(out[1].success)
        self.assertFalse(out[3].success)
        self.assertFalse(out[0].success)
        self.assertEqual(out[1].raw_data["parallel"],
                         "найдена в пачке, перепроверена по одной")

    def test_low_memory_or_failed_start_falls_back(self):
        sc = self._scanner()
        entries = [FakeEntry("s%d" % i) for i in range(3)]
        with mock.patch.object(sc, "_meminfo", return_value=meminfo(512, 10)):
            self.assertEqual(sc._probe_batch(entries, 0), ({}, 1))
        sc._sandbox.start.return_value = False
        with mock.patch.object(sc, "_build_strategy_args",
                               side_effect=lambda e: e.get_args_list()), \
                mock.patch.object(sc, "_ensure_scan_rules", return_value=True), \
                mock.patch.object(sc, "_meminfo",
                                  return_value=meminfo(512, 400)):
            # Не поднялась — новую пачку цикл начнёт за концом этой.
            self.assertEqual(sc._probe_batch(entries, 0), ({}, 3))
            self.assertEqual(sc._parallel, 4)
            sc._probe_batch(entries, 0)
        # Две подряд — дальше по одной.
        self.assertEqual(sc._parallel, 0)
        self.assertIn("дважды", sc._parallel_note)

    def test_decide_parallel(self):
        sc = self._scanner()
        sc._parallel_req = True
        sc._sandbox.supports_option.return_value = True
        sc._decide_parallel(100)
        self.assertEqual(sc._parallel, sp.PAR_MAX)
        sc._decide_parallel(3)
        self.assertEqual(sc._parallel, 0)
        self.assertIn("меньше", sc._parallel_note)
        sc._sandbox.supports_option.return_value = False
        sc._decide_parallel(100)
        self.assertIn("1.0.5", sc._parallel_note)
        sc._parallel_req = False
        sc._decide_parallel(100)
        self.assertEqual((sc._parallel, sc._parallel_note), (0, ""))
        # Галка включена, в настройке число — потолок из настройки.
        sc._parallel_req = True
        sc._sandbox.supports_option.return_value = True
        cfg = mock.Mock()
        cfg.get.return_value = "4"
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg):
            sc._decide_parallel(100)
        self.assertEqual(sc._parallel, 4)

    def test_cancel_drops_unverified_finding(self):
        sc = self._scanner()
        sc._cancelled = True
        entries = [FakeEntry("s%d" % i) for i in range(2)]
        ok = mock.Mock(success=True)
        bad = mock.Mock(success=False)
        with mock.patch.object(sc, "_build_strategy_args",
                               side_effect=lambda e: e.get_args_list()), \
                mock.patch.object(sc, "_meminfo",
                                  return_value=meminfo(512, 400)), \
                mock.patch.object(sc, "_run_batch", return_value=[ok, bad]):
            out, _ = sc._probe_batch(entries, 0)
        self.assertEqual(out, {1: bad})


    def test_recheck_bounded_by_stop_after(self):
        # stop_after=1 — перепроверяется одна находка пачки, не все.
        sc = self._scanner()
        sc._stop_after = 1
        entries = [FakeEntry("s%d" % i) for i in range(3)]
        hits = [mock.Mock(success=True, raw_data={}) for _ in entries]
        solo = mock.Mock(side_effect=lambda e, i: mock.Mock(
            success=True, raw_data={}, strategy_id=e.section_id))
        with mock.patch.object(sc, "_build_strategy_args",
                               side_effect=lambda e: e.get_args_list()), \
                mock.patch.object(sc, "_meminfo",
                                  return_value=meminfo(512, 400)), \
                mock.patch.object(sc, "_run_batch", return_value=hits), \
                mock.patch.object(sc, "_probe_one_strategy", solo):
            out, _ = sc._probe_batch(entries, 0)
        self.assertEqual(solo.call_count, 1)
        self.assertEqual(list(out), [0])


class TestStartRefusal(unittest.TestCase):

    def test_refused_while_safe_apply_waits(self):
        from core.strategy_scanner import StrategyScanner
        sc = StrategyScanner()
        with mock.patch("core.safe_apply.active", return_value=True):
            self.assertFalse(sc.start(target="example.com"))
        self.assertIn("проверкой", sc.refusal)


if __name__ == "__main__":
    unittest.main()
