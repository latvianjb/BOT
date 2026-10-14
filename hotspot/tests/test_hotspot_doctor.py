import contextlib
import datetime as dt
import io
import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import hotspot_doctor as hd  # noqa: E402


def log(*lines):
    return hd.parse_log("\n".join(lines))


IDLE_TIMEOUT_LOG = (
    "2026-10-14 16:00:00.000  1234  1300 I SoftApManager[ap0]: Soft AP is started",
    "2026-10-14 16:00:05.000  1234  1300 D SoftApManager[ap0]: Timeout message scheduled, delay = 600000",
    "2026-10-14 16:10:05.010  1234  1300 I SoftApManager[ap0]: Timeout message received. Stopping soft AP.",
    "2026-10-14 16:10:05.090  1234  1300 D SoftApManager[ap0]: Soft AP is stopped",
)

APP_STOP_LOG = (
    "2026-10-14 17:00:00.000  1234  1400 I WifiService: stopSoftAp uid=10234",
    "2026-10-14 17:00:00.300  1234  1300 D SoftApManager[ap0]: Soft AP is stopped",
)

ENTITLEMENT_LOG = (
    "2026-10-14 18:00:00.000  2000  2100 E EntitlementManager: Tethering provisioning failed, "
    "result=TETHER_ERROR_PROVISIONING_FAILED",
    "2026-10-14 18:00:00.200  2000  2100 I Tethering: stopTethering type=0",
)

WIFI_ON_LOG = (
    "2026-10-14 19:00:00.000  1234  1500 I WifiService: setWifiEnabled package=com.android.systemui "
    "uid=10100 enable=true",
    "2026-10-14 19:00:00.400  1234  1300 D SoftApManager[ap0]: Soft AP is stopped",
)

DATA_SAVER_LOG = (
    "2026-10-14 20:00:00.000  1234  1600 I NetworkPolicy: onRestrictBackgroundChanged(true)",
    "2026-10-14 20:00:00.100  2000  2100 I Tethering: [WIFI] tethering stopped",
)


class ParsingTest(unittest.TestCase):
    def test_parses_year_and_yearless_timestamps(self):
        self.assertEqual(hd.parse_ts("2026-10-14 16:10:05.010  1 2 I T: m", 2000),
                         dt.datetime(2026, 10, 14, 16, 10, 5, 10000))
        self.assertEqual(hd.parse_ts("10-14 16:10:05.010  1 2 I T: m", 2025),
                         dt.datetime(2025, 10, 14, 16, 10, 5, 10000))
        self.assertIsNone(hd.parse_ts("--------- beginning of main", 2026))

    def test_stop_detection(self):
        for line in ("SoftApManager[ap0]: Timeout message received. Stopping soft AP.",
                     "SoftApManager: Soft AP is stopped", "WifiService: stopSoftAp uid=1000",
                     "Tethering: stopTethering type=0", "hostapd: wlan1: AP-DISABLED",
                     "MobileApService: Mobile hotspot turned off"):
            self.assertTrue(hd.is_stop_line(line), line)
        for line in ("SoftApManager: Soft AP is started", "Timeout message scheduled, delay = 600000",
                     "Tethering: startTethering type=0", "OffloadController: tethering offload disabled",
                     "SoftApManager: SoftApConfiguration ... disabled 11ax"):
            self.assertFalse(hd.is_stop_line(line), line)

    def test_stops_close_together_are_one_incident(self):
        self.assertEqual(len(hd.find_stops(log(*IDLE_TIMEOUT_LOG))), 1)
        self.assertEqual(len(hd.find_stops(log(*IDLE_TIMEOUT_LOG, *APP_STOP_LOG))), 2)


class ClassificationTest(unittest.TestCase):
    def only(self, lines, uid_map=None):
        incidents = hd.analyze_log(log(*lines), uid_map or {})
        self.assertEqual(len(incidents), 1)
        return incidents[0]

    def test_idle_timeout(self):
        inc = self.only(IDLE_TIMEOUT_LOG)
        self.assertEqual(inc.strong[0].key, "idle_timeout")
        self.assertIn("Timeout message received", inc.strong[0].evidence[0])

    def test_app_is_named_through_uid(self):
        inc = self.only(APP_STOP_LOG, {10234: ["net.dinglisch.android.taskerm"]})
        self.assertEqual(inc.strong[0].key, "actor_app")
        self.assertIn("net.dinglisch.android.taskerm", inc.strong[0].title)

    def test_settings_uid_is_not_blamed_as_app(self):
        inc = self.only(("2026-10-14 17:00:00.000  1 2 I WifiService: stopSoftAp uid=1000",))
        self.assertFalse(inc.strong)
        self.assertEqual(inc.weak[0].key, "actor_system")

    def test_turning_hotspot_back_on_is_not_blamed(self):
        lines = ("2026-10-14 17:00:00.000  1 2 D SoftApManager: Soft AP is stopped",
                 "2026-10-14 17:00:01.000  1 2 I WifiService: setWifiApEnabled(null, true) uid=10234",
                 "2026-10-14 17:00:04.000  1 2 I WifiService: stopSoftAp uid=10234")
        inc = self.only(lines, {10234: ["com.example.automation"]})
        self.assertFalse(inc.strong)

    def test_operator_entitlement(self):
        inc = self.only(ENTITLEMENT_LOG)
        self.assertEqual([h.key for h in inc.strong], ["entitlement"])

    def test_wifi_turned_on(self):
        inc = self.only(WIFI_ON_LOG)
        self.assertEqual([h.key for h in inc.strong], ["wifi_concurrency"])

    def test_data_saver(self):
        inc = self.only(DATA_SAVER_LOG)
        self.assertEqual([h.key for h in inc.strong], ["data_saver"])

    def test_old_evidence_outside_lookback_is_ignored(self):
        lines = ("2026-10-14 19:00:00.000  1 2 I WifiService: setWifiEnabled package=x uid=10100 enable=true",
                 "2026-10-14 19:01:30.000  1 2 D SoftApManager: Soft AP is stopped")
        self.assertFalse(self.only(lines).strong)

    def test_unknown_cause_shows_context(self):
        lines = ("2026-10-14 21:00:00.000  1 2 I WifiNative: something about wlan1",
                 "2026-10-14 21:00:01.000  1 2 D SoftApManager: Soft AP is stopped")
        inc = self.only(lines)
        self.assertFalse(inc.strong)
        self.assertIn("Iemesls žurnālā nav skaidri redzams", hd.render_incident(inc, 1))
        self.assertTrue(any("WifiNative" in c for c in inc.context))


class SnapshotTest(unittest.TestCase):
    def test_android13_auto_shutdown_and_operator(self):
        snap = {
            "getprop.txt": "[ro.build.version.sdk]: [33]\n[ro.product.model]: [SM-A525F]\n",
            "settings_global.txt": "wifi_on=1\nwifi_wakeup_enabled=1\nlow_power=0\n",
            "dumpsys_wifi.txt": " \n AutoShutdownEnabled = true \n ShutdownTimeoutMillis = 600000\n",
            "dumpsys_tethering.txt": "  isCellularUpstreamPermitted: false\n",
            "netpolicy.txt": "Restrict background status: disabled\n",
        }
        titles = {f.title: f for f in hd.check_snapshot(snap)}
        self.assertIn("~10 min", titles["Ieslēgta hotspota automātiskā izslēgšanās"].detail)
        self.assertEqual(titles["Operators šobrīd NEATĻAUJ koplietot mobilo internetu"].level, "!")
        self.assertIn("Ieslēgts «Automātiski ieslēgt Wi-Fi»", titles)
        self.assertNotIn("Ieslēgts datu taupīšanas režīms (Data Saver)", titles)

    def test_android10_default_timeout_and_data_saver(self):
        snap = {"getprop.txt": "[ro.build.version.sdk]: [29]\n",
                "settings_global.txt": "wifi_on=0\n",
                "netpolicy.txt": "Restrict background status: enabled\n"}
        titles = [f.title for f in hd.check_snapshot(snap)]
        self.assertIn("Ieslēgta hotspota automātiskā izslēgšanās", titles)
        self.assertIn("Ieslēgts datu taupīšanas režīms (Data Saver)", titles)

    def test_clean_phone_has_no_problems(self):
        snap = {"getprop.txt": "[ro.build.version.sdk]: [34]\n",
                "settings_global.txt": "wifi_on=0\nwifi_wakeup_enabled=0\n",
                "dumpsys_wifi.txt": "AutoShutdownEnabled = false\n",
                "netpolicy.txt": "Restrict background status: disabled\n"}
        self.assertEqual([f for f in hd.check_snapshot(snap) if f.level == "!"], [])


class WatcherTest(unittest.TestCase):
    def test_reports_once_after_context_arrives(self):
        out = []
        watcher = hd.Watcher({}, out.append, year=2026)
        for line in IDLE_TIMEOUT_LOG:
            watcher.feed(line)
        self.assertEqual(watcher.count, 0)  # still waiting for the lines after the stop
        watcher.feed("2026-10-14 16:10:11.000  1 2 I Tethering: unrelated later line")
        self.assertEqual(watcher.count, 1)
        self.assertIn("Automātiskā izslēgšanās", "\n".join(out))

    def test_force_flush(self):
        out = []
        watcher = hd.Watcher({}, out.append, year=2026)
        for line in ENTITLEMENT_LOG:
            watcher.feed(line)
        watcher.tick(force=True)
        self.assertEqual(watcher.count, 1)
        self.assertIn("Operatora serveris", "\n".join(out))


FAKE_ADB = textwrap.dedent("""\
    import json, os, sys
    args = sys.argv[1:]
    if args[:1] == ["-s"]:
        args = args[2:]
    with open(os.environ["FAKE_ADB_CALLS"], "a") as fh:
        fh.write(" ".join(args) + "\\n")
    responses = json.load(open(os.environ["FAKE_ADB_DATA"]))
    key = " ".join(args)
    best = max((k for k in responses if key.startswith(k)), key=len, default=None)
    sys.stdout.write(responses[best] if best is not None else "")
""")


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        script = self.tmp / "fake_adb.py"
        script.write_text(FAKE_ADB)
        self.adb = self.tmp / "adb"
        self.adb.write_text(f"#!{sys.executable}\nexec(open({str(script)!r}).read())\n")
        self.adb.chmod(self.adb.stat().st_mode | stat.S_IEXEC)
        self.calls = self.tmp / "calls.txt"
        os.environ["FAKE_ADB_CALLS"] = str(self.calls)

    def responses(self, data):
        path = self.tmp / "responses.json"
        path.write_text(json.dumps(data))
        os.environ["FAKE_ADB_DATA"] = str(path)

    def run_main(self, *argv, stdin=""):
        out = io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out):
                rc = hd.main(["--adb", str(self.adb), *argv])
        finally:
            sys.stdin = old_stdin
        return rc, out.getvalue()

    def test_diagnose_writes_report(self):
        self.responses({
            "get-state": "device\n",
            "shell getprop": "[ro.build.version.sdk]: [33]\n[ro.product.manufacturer]: [samsung]\n"
                             "[ro.product.model]: [SM-A525F]\n[ro.build.version.release]: [13]\n",
            "shell settings list global": "wifi_on=0\n",
            "shell pm list packages -U": "package:com.example.automation uid:10234\n",
            "shell dumpsys wifi": "AutoShutdownEnabled = true\n",
            "shell cmd netpolicy get restrict-background": "Restrict background status: disabled\n",
            "logcat -d": "\n".join(IDLE_TIMEOUT_LOG + APP_STOP_LOG) + "\n",
        })
        rc, out = self.run_main("diagnose", "--out", str(self.tmp))
        self.assertEqual(rc, 0)
        self.assertIn("HOTSPOTA IZSLĒGŠANĀS GADĪJUMI: 2", out)
        self.assertIn("Hotspotu izslēdza lietotne: com.example.automation", out)
        self.assertIn("samsung SM-A525F, Android 13", out)
        report_dirs = list(self.tmp.glob("hotspot-report-*"))
        self.assertEqual(len(report_dirs), 1)
        self.assertTrue((report_dirs[0] / "report.txt").is_file())
        rc, out = self.run_main("analyze", str(report_dirs[0]))
        self.assertIn("HOTSPOTA IZSLĒGŠANĀS GADĪJUMI: 2", out)

    def test_fix_on_android10(self):
        self.responses({
            "get-state": "device\n",
            "shell getprop": "[ro.build.version.sdk]: [29]\n",
            "shell settings list global": "wifi_wakeup_enabled=1\nlow_power=0\n",
            "shell cmd netpolicy get restrict-background": "Restrict background status: enabled\n",
        })
        rc, out = self.run_main("fix", "--yes")
        self.assertEqual(rc, 0)
        calls = self.calls.read_text()
        self.assertIn("logcat -G 16M", calls)
        self.assertIn("shell settings put global soft_ap_timeout_enabled 0", calls)
        self.assertIn("shell cmd netpolicy set restrict-background false", calls)
        self.assertIn("shell settings put global wifi_wakeup_enabled 0", calls)
        self.assertNotIn("low_power 0", calls)
        self.assertNotIn("tether_offload_disabled", calls)

    def test_fix_asks_and_skips_on_no(self):
        self.responses({"get-state": "device\n", "shell getprop": "[ro.build.version.sdk]: [34]\n"})
        rc, out = self.run_main("fix", stdin="n\n")
        self.assertEqual(rc, 0)
        self.assertNotIn("logcat -G", self.calls.read_text())
        self.assertIn("Automātiski izslēgt tīklāju", out)

    def test_missing_device(self):
        self.responses({"get-state": "error: no devices/emulators found\n"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc, _ = self.run_main("diagnose", "--out", str(self.tmp))
        self.assertEqual(rc, 2)
        self.assertIn("Telefons nav atrasts", err.getvalue())


if __name__ == "__main__":
    unittest.main()
