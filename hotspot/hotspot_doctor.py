#!/usr/bin/env python3
"""Hotspot Doctor — noskaidro, kāpēc Android telefonā pats izslēdzas Wi-Fi hotspots (tīklājs).

Rīks caur ADB nolasa telefona sistēmas žurnālu (logcat) un iestatījumus, atrod katru
brīdi, kad hotspots izslēdzās, un pasaka, kas to izdarīja un ko darīt.

    python3 hotspot_doctor.py diagnose        # momentuzņēmums + pēdējo žurnālu analīze
    python3 hotspot_doctor.py watch           # dzīvā uzraudzība: noķer nākamo izslēgšanos
    python3 hotspot_doctor.py fix             # droši labojumi (jautā pirms katra)
    python3 hotspot_doctor.py analyze MAPE    # atkārtoti analizēt saglabātu atskaiti vai žurnālu

Vajag: Python 3.8+, Android platform-tools (adb) un telefonā ieslēgtu USB atkļūdošanu.
"""

from __future__ import annotations

import argparse
import bisect
import datetime as dt
import queue
import re
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

LogLine = Tuple[dt.datetime, str]

LOG_BUFFER_SIZE = "16M"
INCIDENT_GAP = dt.timedelta(seconds=15)
CONTEXT_AFTER = dt.timedelta(seconds=5)
MAX_LOOKBACK = dt.timedelta(seconds=120)
WATCH_WALL_WAIT = 8.0
MAX_EVIDENCE = 4
MAX_CONTEXT = 25
MAX_DETAILED_INCIDENTS = 10

# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

# "2026-10-14 17:44:01.123  1234  1250 I Tag: msg" (-v year) or "10-14 17:44:01.123 ..."
TS_RE = re.compile(r"^\s*(?:(\d{4})-)?(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})")


def parse_ts(line: str, default_year: int) -> Optional[dt.datetime]:
    m = TS_RE.match(line)
    if not m:
        return None
    year = int(m.group(1)) if m.group(1) else default_year
    try:
        return dt.datetime(year, int(m.group(2)), int(m.group(3)), int(m.group(4)),
                           int(m.group(5)), int(m.group(6)), int(m.group(7)) * 1000)
    except ValueError:
        return None


def parse_log(text: str, default_year: Optional[int] = None) -> List[LogLine]:
    """Returns the timestamped lines, sorted by time (logcat merges buffers almost in order)."""
    year = default_year or dt.date.today().year
    lines = []
    for raw in text.splitlines():
        raw = raw.rstrip("\r")
        ts = parse_ts(raw, year)
        if ts is not None:
            lines.append((ts, raw))
    lines.sort(key=lambda item: item[0])
    return lines


_AP = r"(?:soft ?ap\w*|hotspot|mobile ?ap\b|wifi ?ap\b|tethering)"
_OFF = r"(?:stop(?:ped|ping)?|disabl(?:ed|ing)|turn(?:ed|ing)? off|shut(?:ting)? ?down|tear(?:ing)? ?down)"

STOP_RE = re.compile(
    rf"{_AP}.{{0,80}}?\b{_OFF}\b"
    rf"|\b{_OFF}\b.{{0,40}}?{_AP}"
    r"|soft ?ap\w*.{0,60}?\bfail(?:ed|ure)?\b"
    r"|\b(?:stopSoftAp|stopTethering)\b|setWifiApEnabled\(.{0,30}?false"
    r"|AP-DISABLED|WIFI_AP_STATE_(?:DISABLING|DISABLED|FAILED)",
    re.I,
)
# Config dumps and offload chatter mention "tethering ... disabled" without the hotspot stopping.
STOP_EXCLUDE_RE = re.compile(r"offload|configuration|\bconfig\b|isTetheringSupported", re.I)


def is_stop_line(text: str) -> bool:
    return bool(STOP_RE.search(text)) and not STOP_EXCLUDE_RE.search(text)


RELEVANT_RE = re.compile(
    r"wifi|wi-fi|soft ?ap|hostapd|tether|hotspot|mobile ?ap|entitlement|provision|thermal|"
    r"upstream|netpolicy|restrict ?background|battery ?saver|low ?power|power ?sav|HalDevice|"
    r"ActiveModeWarden|IpServer|wlan|\bdfs\b|radar|offload",
    re.I,
)

# ---------------------------------------------------------------------------
# Causes
# ---------------------------------------------------------------------------

AUTO_OFF_FIX = (
    "Izslēdz automātisko izslēgšanos. Android (Pixel u.c.): Iestatījumi -> Tīkls un internets -> "
    "Tīklājs un piesaiste -> Wi-Fi tīklājs -> «Automātiski izslēgt tīklāju» (Turn off hotspot "
    "automatically) -> izslēgts. Samsung: Settings -> Connections -> Mobile Hotspot and Tethering -> "
    "Mobile Hotspot -> ⋮ -> Configure -> Advanced -> «Turn off when no device connected» -> Never. "
    "Xiaomi/Redmi: Connection & sharing -> Portable hotspot -> «Turn off hotspot automatically» -> "
    "izslēgts. Android 10 un vecākiem to izdara `hotspot_doctor.py fix`."
)

OPERATOR_FIX = (
    "Sazinies ar operatoru un pārbaudi, vai tarifā ir atļauta interneta koplietošana (hotspots/"
    "tethering) un vai nav iztērēts tās datu apjoms. Atiestati APN uz noklusējumu (Mobilais tīkls -> "
    "Piekļuves punktu nosaukumi -> ⋮ -> Atiestatīt) un atjaunini telefona programmatūru. "
    "Ja pārbaudes serveris neatbild, palīdz arī mobilo datu izslēgšana/ieslēgšana."
)


@dataclass
class Cause:
    key: str
    title: str
    why: str
    fix: str
    patterns: Sequence[str]
    lookback: int = 60  # seconds before the stop that still count as evidence
    strong: bool = True
    regexes: List["re.Pattern[str]"] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regexes = [re.compile(p, re.I) for p in self.patterns]

    def evidence(self, window: Sequence[LogLine], t: dt.datetime) -> List[str]:
        start = t - dt.timedelta(seconds=self.lookback)
        return [text for ts, text in window
                if ts >= start and any(r.search(text) for r in self.regexes)]


CAUSES: List[Cause] = [
    Cause(
        "idle_timeout",
        "Automātiskā izslēgšanās, jo hotspotam nebija pieslēgtu ierīču (taimauts)",
        "Android izslēdz hotspotu, ja noteiktu laiku (parasti 5-10 min) tam nav pieslēgta neviena "
        "ierīce. Tas notiek arī tad, ja dators/TV/planšete aizmieg vai uz brīdi atvienojas.",
        AUTO_OFF_FIX,
        # "... Timeout message received but has clients. Dropping." and similar lines are not stops.
        [r"^(?!.*dropp).*?Timeout message received",
         r"^(?!.*(?:schedul|cancel|remov|dropp)).*?soft ?ap\w*\W.{0,100}?\b(?:time ?out|timed out|idle)\b",
         r"\b(?:no|without) (?:connected )?(?:clients?|devices?|stations?)\b.{0,80}?"
         r"\b(?:time ?out|timer|expir\w*|stop\w*|shut\w*|turn\w* off)\b",
         r"\b(?:timer|time ?out)\b.{0,40}?\bexpir\w*.{0,60}?(?:hotspot|soft ?ap|mobile ?ap|tether)",
         r"\bidle instance\b|shutdownIdleInstance"],
        lookback=5,
    ),
    Cause(
        "entitlement",
        "Operatora serveris neatļāva hotspotu (tethering entitlement / provisioning pārbaude)",
        "Daļa operatoru liek telefonam, ieslēdzot hotspotu un periodiski arī vēlāk, savā serverī "
        "pārbaudīt, vai tarifs atļauj koplietot internetu. Ja pārbaude neizdodas vai serveris "
        "neatbild, Android hotspotu izslēdz. Šis ir vienīgais ārējais serveris, kas var izslēgt hotspotu.",
        OPERATOR_FIX,
        [r"(?:entitlement|provision\w*)\W.{0,100}?\b(?:fail\w*|denied|reject\w*|error|not (?:allowed|"
         r"permitted|entitled)|unknown|invalid|timeout|timed out)\b",
         r"TETHER_ERROR_(?:PROVISION\w*|ENTITLEMENT\w*)",
         r"isCellularUpstreamPermitted\W+false",
         r"\b(?:cellular|mobile) upstream (?:is )?not permitted"],
        lookback=60,
    ),
    Cause(
        "thermal",
        "Telefons pārkarsa",
        "Hotspots + mobilie dati (īpaši 5G) + uzlāde stipri silda telefonu. Pārkarstot sistēma "
        "izslēdz hotspotu vai ierobežo radio.",
        "Noņem vāciņu, neturi telefonu saulē vai uz mīksta, hotspota laikā nelādē ar ātro lādētāju, "
        "izvēlies 2,4 GHz joslu, vājā 5G signālā pārslēdz tīklu uz 4G/LTE.",
        [r"\b(?:overheat\w*|too hot|high temperature|temperature (?:is )?too high)\b",
         r"thermal\w*\W.{0,100}?\b(?:hotspot|tether\w*|soft ?ap|mobile ?ap)\b",
         r"\b(?:hotspot|tether\w*|soft ?ap|mobile ?ap)\W.{0,100}?\b(?:thermal|overheat\w*)",
         r"thermal (?:status|severity)\W{1,3}(?:[3-6]|severe|critical|emergency|shutdown)\b"],
        lookback=120,
    ),
    Cause(
        "wifi_concurrency",
        "Ieslēdzās Wi-Fi, un telefons nespēj vienlaikus darbināt Wi-Fi un hotspotu",
        "Daudzi telefoni neatbalsta Wi-Fi klientu + hotspotu vienlaikus. Kad Wi-Fi ieslēdzas (pats "
        "lietotājs, «Automātiski ieslēgt Wi-Fi» pie saglabāta tīkla, Samsung Intelligent Wi-Fi, "
        "rutīna), sistēma hotspotu noņem.",
        "Izslēdz «Automātiski ieslēgt Wi-Fi» (Iestatījumi -> Tīkls un internets -> Internets -> "
        "Tīkla preferences; Samsung: Wi-Fi -> ⋮ -> Intelligent Wi-Fi) — `hotspot_doctor.py fix` to "
        "izdara. Neieslēdz Wi-Fi, kamēr lieto hotspotu.",
        [r"setWifiEnabled\b.{0,160}?\benable\s*[=:]\s*true",
         r"WakeupController\W.{0,160}?\b(?:enabl\w*|wak\w*|turn\w* on)\b"],
        lookback=15,
    ),
    Cause(
        "data_saver",
        "Ieslēdzās datu taupīšanas režīms (Data Saver)",
        "Kad ieslēdz «Datu lietojuma samazinātāju», Android aptur interneta koplietošanu.",
        "Iestatījumi -> Tīkls un internets -> Datu lietojuma samazinātājs -> izslēgts "
        "(`hotspot_doctor.py fix` to izdara).",
        [r"onRestrictBackgroundChanged\W.{0,20}?\btrue\b",
         r"(?:data ?saver|restrict ?background)\w*\W.{0,60}?\b(?:true|enabled|on)\b"],
        lookback=15,
    ),
    Cause(
        "battery_saver",
        "Akumulatora taupīšanas režīms",
        "Daži ražotāji (Samsung, Xiaomi, Huawei u.c.) enerģijas taupīšanas režīmā izslēdz hotspotu "
        "vai ierobežo Wi-Fi radio.",
        "Kamēr lieto hotspotu, izslēdz akumulatora taupīšanu un pieslēdz lādētāju.",
        [r"(?:battery ?saver|power ?sav\w*|low ?power\w*)\W.{0,60}?\b(?:true|enabled|on|activated|"
         r"started)\b",
         r"\blow_power\W{1,3}1\b"],
        lookback=30,
        strong=False,
    ),
    Cause(
        "upstream",
        "Pazuda mobilais internets (vājš signāls, 4G/5G pārslēgšanās vai datu limits)",
        "Hotspots dalās ar telefona mobilo internetu. Ja tas pazūd, ierīces paliek bez interneta, un "
        "daļa telefonu tad hotspotu izslēdz.",
        "Ja 5G signāls ir vājš, iestati «Vēlamais tīkla veids» uz 4G/LTE; pārbaudi datu limitu "
        "(Mobilais tīkls -> Datu brīdinājums un ierobežojums); novieto telefonu vietā ar labāku signālu.",
        [r"UpstreamNetworkMonitor\W.{0,120}?\b(?:lost|onLost|null|none|no upstream)\b",
         r"\bno upstream\b",
         r"\bupstream\b.{0,60}?\b(?:lost|null|none|unavailable)\b",
         r"\b(?:mobile data|data_?enabled)\b.{0,60}?\b(?:false|disabled|off)\b",
         r"\bdata limit\b",
         r"DataRegState\W{1,3}\d*\(?(?:OUT_OF_SERVICE|POWER_OFF)"],
        lookback=60,
        strong=False,
    ),
    Cause(
        "offload",
        "Piesaistes aparatūras paātrinājuma (tethering offload) kļūda",
        "Mobilā modema aparatūras paātrinājums dažiem telefoniem (Qualcomm/MediaTek) uzkaras un "
        "pārtrauc hotspotu.",
        "Izstrādātāja opcijas -> «Piesaistes aparatūras paātrinājums» (Tethering hardware "
        "acceleration) -> izslēgts (`hotspot_doctor.py fix --disable-offload`).",
        [r"(?:OffloadController|OffloadHardwareInterface|IOffloadControl|OffloadHal)\W.{0,120}?"
         r"\b(?:fail\w*|error|died|death|stop\w*|crash\w*)\b"],
        lookback=30,
        strong=False,
    ),
    Cause(
        "dfs",
        "5 GHz DFS kanāls / radara noteikšana",
        "Ja hotspots strādā 5 GHz DFS kanālā un tiek uztverts radara signāls (lidostas, meteoradari), "
        "piekļuves punkts obligāti jāpārslēdz vai jāizslēdz.",
        "Hotspota iestatījumos izvēlies 2,4 GHz joslu (vai «Saderības režīms»/«Maximize compatibility»).",
        [r"\bDFS\b.{0,80}?\b(?:radar|cac|fail\w*|channel switch|nop)\b",
         r"\bradar\b.{0,40}?\bdetect\w*",
         r"DFS-RADAR|DFS-CAC|CHANNEL_SWITCH"],
        lookback=30,
        strong=False,
    ),
    Cause(
        "driver",
        "Wi-Fi draivera vai aparātprogrammatūras kļūda",
        "Wi-Fi mikroshēmas programmatūra (hostapd/draiveris) avarēja vai atteicās darboties, un "
        "sistēma hotspotu apturēja.",
        "Restartē telefonu un atjaunini programmatūru; izvēlies 2,4 GHz joslu; izslēdz «Piesaistes "
        "aparatūras paātrinājums»; ja atkārtojas — Iestatījumi -> Sistēma -> Atiestatīšana -> "
        "«Atiestatīt Wi-Fi, mobilo tīklu un Bluetooth».",
        [r"\b(?:hostapd|HostapdHal|wificond|cnss\w*|wcnss\w*|vendor\.wifi\w*|WifiHal\w*)\b.{0,160}?"
         r"\b(?:crash\w*|died|death|panic|abort\w*|fw ?dump|recovery|ssr|fatal|fail\w*)\b",
         r"SoftApManager\W.{0,160}?\b(?:onFailure|fail\w*|error)\b",
         r"AP-DISABLED|WIFI_AP_STATE_FAILED",
         r"subsystem restart.{0,40}?(?:wlan|wifi)"],
        lookback=30,
        strong=False,
    ),
]

# ---------------------------------------------------------------------------
# Who asked the hotspot to stop (user, app or system)
# ---------------------------------------------------------------------------

ACTOR_CALL_RE = re.compile(
    r"\b(?:setWifiApEnabled|stopSoftAp|stopTethering|setWifiTethering|stopLocalOnlyHotspot|"
    r"setSoftApConfiguration|setWifiApConfiguration)\b", re.I)
PKG_FIELD_RE = re.compile(
    r"\b(?:package(?:Name)?|pkg|callingPackage|caller(?:Pkg|Package)?)\s*[=:]\s*([A-Za-z][\w.]*)", re.I)
UID_FIELD_RE = re.compile(r"\b(?:calling)?uid\s*[=:]\s*(\d+)", re.I)
ENABLE_CALL_RE = re.compile(r"(?:setWifiApEnabled|setWifiTethering)\W.{0,40}?\btrue\b", re.I)
USER_UI_HINTS = ("settings", "systemui", "launcher")
SYSTEM_UIDS = {0: "root", 1000: "Android sistēma vai Iestatījumu lietotne", 1001: "telefona/radio serviss",
               1010: "Wi-Fi serviss", 1073: "tīkla serviss", 2000: "adb shell"}
ACTOR_LOOKBACK = dt.timedelta(seconds=10)
ACTOR_AFTER = dt.timedelta(seconds=2)


@dataclass
class Hit:
    title: str
    why: str
    fix: str
    evidence: List[str]
    key: str = ""


def _actor_hit(window: Sequence[LogLine], t: dt.datetime,
               uid_map: Dict[int, List[str]]) -> Tuple[Optional[Hit], bool]:
    """Finds the API call that stopped the hotspot and names its caller. Returns (hit, strong)."""
    calls = [text for ts, text in window
             if t - ACTOR_LOOKBACK <= ts <= t + ACTOR_AFTER
             and ACTOR_CALL_RE.search(text) and not ENABLE_CALL_RE.search(text)]
    apps, ui, system = [], [], []
    for text in calls:
        pkgs = PKG_FIELD_RE.findall(text)
        for uid_s in UID_FIELD_RE.findall(text):
            uid = int(uid_s)
            if uid >= 10000:
                pkgs.extend(uid_map.get(uid, [f"uid {uid}"]))
            else:
                system.append(f"uid {uid} ({SYSTEM_UIDS.get(uid, 'sistēmas process')})")
        for pkg in pkgs:
            if pkg == "android" or pkg.startswith("com.android.server"):
                system.append(pkg)
            elif any(h in pkg.lower() for h in USER_UI_HINTS):
                ui.append(pkg)
            else:
                apps.append(pkg)
    evidence = calls[-MAX_EVIDENCE:]
    if apps:
        names = ", ".join(sorted(set(apps)))
        return Hit(
            f"Hotspotu izslēdza lietotne: {names}",
            "Šī lietotne (automatizācija, rutīna, VPN/MDM, «akumulatora optimizētājs» u.tml.) izsauca "
            "hotspota izslēgšanu.",
            f"Atver Iestatījumi -> Lietotnes -> {names} un atslēdz tās automatizāciju/rutīnu, atņem "
            "atļauju «Mainīt sistēmas iestatījumus» vai atinstalē. Samsung: pārbaudi arī «Modes and "
            "Routines».",
            evidence, "actor_app"), True
    if ui:
        return Hit(
            "Hotspotu izslēdza lietotājs (Iestatījumi vai ātro iestatījumu slēdzis)",
            "Izslēgšana nāca no Iestatījumiem/SystemUI — parasti tas ir slēdža pieskāriens (arī nejaušs, "
            "kabatā) vai ražotāja «viedā» funkcija Iestatījumu lietotnē.",
            "Ja neviens to neizslēdza ar roku, pārbaudi ražotāja rutīnas un bloķē ekrānu kabatā.",
            evidence, "actor_ui"), True
    if system:
        return Hit(
            f"Izslēgšanu pieprasīja sistēmas process: {', '.join(sorted(set(system)))}",
            "Hotspotu apturēja pati sistēma; precīzāku iemeslu skaties pārējos ierakstos.",
            "", evidence, "actor_system"), False
    return None, False


# ---------------------------------------------------------------------------
# Incident analysis
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    ts: dt.datetime
    trigger: str
    strong: List[Hit] = field(default_factory=list)
    weak: List[Hit] = field(default_factory=list)
    context: List[str] = field(default_factory=list)


def find_stops(lines: Sequence[LogLine]) -> List[LogLine]:
    stops: List[LogLine] = []
    for ts, text in lines:
        if is_stop_line(text) and not (stops and ts - stops[-1][0] <= INCIDENT_GAP):
            stops.append((ts, text))
    return stops


def _window(lines: Sequence[LogLine], keys: Sequence[dt.datetime],
            start: dt.datetime, end: dt.datetime) -> Sequence[LogLine]:
    return lines[bisect.bisect_left(keys, start):bisect.bisect_right(keys, end)]


def analyze_incident(lines: Sequence[LogLine], t: dt.datetime, trigger: str,
                     uid_map: Dict[int, List[str]],
                     keys: Optional[Sequence[dt.datetime]] = None) -> Incident:
    keys = keys if keys is not None else [ts for ts, _ in lines]
    window = _window(lines, keys, t - MAX_LOOKBACK, t + CONTEXT_AFTER)
    inc = Incident(t, trigger)
    actor, actor_strong = _actor_hit(window, t, uid_map)
    if actor:
        (inc.strong if actor_strong else inc.weak).append(actor)
    for cause in CAUSES:
        ev = cause.evidence(window, t)
        if ev:
            hit = Hit(cause.title, cause.why, cause.fix, ev[-MAX_EVIDENCE:], cause.key)
            (inc.strong if cause.strong else inc.weak).append(hit)
    recent = t - dt.timedelta(seconds=30)
    inc.context = [text for ts, text in window if ts >= recent and RELEVANT_RE.search(text)][-MAX_CONTEXT:]
    return inc


def analyze_log(lines: Sequence[LogLine], uid_map: Dict[int, List[str]]) -> List[Incident]:
    keys = [ts for ts, _ in lines]
    return [analyze_incident(lines, ts, text, uid_map, keys) for ts, text in find_stops(lines)]


# ---------------------------------------------------------------------------
# Phone settings snapshot
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    level: str  # "!" = problem, "i" = information
    title: str
    detail: str = ""
    fix: str = ""


def parse_getprop(text: str) -> Dict[str, str]:
    return dict(re.findall(r"^\[(.+?)\]: \[(.*)\]\s*$", text, re.M))


def parse_settings(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


def parse_packages(text: str) -> Dict[int, List[str]]:
    uid_map: Dict[int, List[str]] = {}
    for pkg, uid in re.findall(r"package:(\S+)\s+uid:(\d+)", text):
        uid_map.setdefault(int(uid), []).append(pkg)
    return uid_map


def _sdk(props: Dict[str, str]) -> int:
    try:
        return int(props.get("ro.build.version.sdk", "0"))
    except ValueError:
        return 0


def check_snapshot(snap: Dict[str, str]) -> List[Finding]:
    props = parse_getprop(snap.get("getprop.txt", ""))
    sdk = _sdk(props)
    glob = parse_settings(snap.get("settings_global.txt", ""))
    system = parse_settings(snap.get("settings_system.txt", ""))
    wifi = snap.get("dumpsys_wifi.txt", "")
    tethering = snap.get("dumpsys_tethering.txt", "") + snap.get("dumpsys_connectivity_tethering.txt", "")
    carrier = snap.get("dumpsys_carrier_config.txt", "")
    out: List[Finding] = []

    auto_values = [v.lower() for v in re.findall(r"AutoShutdown(?:Enabled)?\s*[=:]\s*(true|false)", wifi, re.I)]
    legacy_timeout = glob.get("soft_ap_timeout_enabled")
    legacy_default_on = bool(glob) and 0 < sdk <= 29 and legacy_timeout is None
    if "true" in auto_values or legacy_timeout == "1" or legacy_default_on:
        timeout = re.search(r"ShutdownTimeoutMillis\s*[=:]\s*(\d+)", wifi)
        minutes = int(timeout.group(1)) // 60000 if timeout and int(timeout.group(1)) > 0 else 0
        detail = (f"Hotspots izslēgsies pēc ~{minutes} min bez pieslēgtām ierīcēm." if minutes
                  else "Hotspots izslēgsies, ja kādu laiku (parasti 5-10 min) nebūs pieslēgtu ierīču.")
        out.append(Finding("!", "Ieslēgta hotspota automātiskā izslēgšanās", detail, AUTO_OFF_FIX))

    oem_keys = sorted(f"{k}={v}" for k, v in {**glob, **system}.items()
                      if re.search(r"(hotspot|soft_?ap|wifi_ap|mobile_?ap|tether)", k, re.I)
                      and re.search(r"(time|auto|off|sleep|idle)", k, re.I))
    if oem_keys:
        out.append(Finding("i", "Ražotāja hotspota taimauta iestatījumi", "; ".join(oem_keys)))

    netpolicy = snap.get("netpolicy.txt", "")
    if re.search(r"\benabled\b", netpolicy, re.I):
        out.append(Finding("!", "Ieslēgts datu taupīšanas režīms (Data Saver)",
                           "Datu taupītājs aptur interneta koplietošanu.", CAUSES_BY_KEY["data_saver"].fix))

    if glob.get("low_power") == "1":
        out.append(Finding("!", "Ieslēgts akumulatora taupīšanas režīms",
                           "Daži telefoni tad izslēdz hotspotu.", CAUSES_BY_KEY["battery_saver"].fix))

    concurrency = re.search(r"StaApConcurrency\w*\W{1,3}(true|false)", wifi, re.I)
    if glob.get("wifi_on") in ("1", "2"):
        if concurrency and concurrency.group(1).lower() == "false":
            out.append(Finding("!", "Wi-Fi ir ieslēgts, bet telefons neatbalsta Wi-Fi + hotspotu vienlaikus",
                               "Wi-Fi savienojums noņems hotspotu.", CAUSES_BY_KEY["wifi_concurrency"].fix))
        else:
            out.append(Finding("i", "Wi-Fi ir ieslēgts vienlaikus ar hotspotu",
                               "Ja telefons neatbalsta abus vienlaikus, Wi-Fi savienojums hotspotu noņems."))
    if glob.get("wifi_wakeup_enabled") == "1":
        out.append(Finding("i", "Ieslēgts «Automātiski ieslēgt Wi-Fi»",
                           "Pie saglabāta tīkla Wi-Fi ieslēgsies pats un var noņemt hotspotu.",
                           CAUSES_BY_KEY["wifi_concurrency"].fix))

    if re.search(r"isCellularUpstreamPermitted\W+false", tethering, re.I):
        out.append(Finding("!", "Operators šobrīd NEATĻAUJ koplietot mobilo internetu",
                           "Telefona entitlement pārbaude operatora serverī ir negatīva.", OPERATOR_FIX))
    provisioning_app = re.search(r"provisioningApp\W+\[?([^\]\r\n]*)", tethering)
    requires_check = re.search(r"require_entitlement_checks_bool\W+true", carrier, re.I)
    if requires_check or (provisioning_app and provisioning_app.group(1).strip(" ,")):
        detail = "Telefons pirms hotspota ieslēgšanas un periodiski pārbauda atļauju operatora serverī."
        if provisioning_app and provisioning_app.group(1).strip(" ,"):
            detail += f" Pārbaudes lietotne: {provisioning_app.group(1).strip()}."
        out.append(Finding("i", "Operators pieprasa hotspota atļaujas pārbaudi (entitlement)", detail))

    thermal = re.search(r"Thermal Status:\s*(\d)", snap.get("dumpsys_thermalservice.txt", ""))
    if thermal and int(thermal.group(1)) >= 2:
        out.append(Finding("!", f"Telefons ir sakarsis (thermal status {thermal.group(1)})",
                           "Sistēma var ierobežot vai izslēgt hotspotu.", CAUSES_BY_KEY["thermal"].fix))

    if glob.get("tether_offload_disabled") == "1":
        out.append(Finding("i", "Piesaistes aparatūras paātrinājums jau ir izslēgts"))
    return out


CAUSES_BY_KEY = {c.key: c for c in CAUSES}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

SERVERS_NOTE = (
    "Par serveriem: hotspotu izslēdz pats telefons (Android SoftApManager/Tethering serviss). "
    "Interneta serveri, ar kuriem sazinās lietotnes, to izslēgt nevar. Vienīgais ārējais serveris, "
    "kas to var ietekmēt, ir operatora atļaujas (entitlement) pārbaude. Operators var arī pamanīt "
    "koplietošanu (pēc TTL) un ierobežot ātrumu — tad hotspots paliek ieslēgts, bet internets pazūd."
)


def _clip(text: str, limit: int = 300) -> str:
    return text if len(text) <= limit else text[:limit] + " …"


def render_incident(inc: Incident, index: int) -> str:
    out = [f"[{index}] {inc.ts:%Y-%m-%d %H:%M:%S}",
           f"    Izslēgšanās ieraksts: {_clip(inc.trigger, 200)}"]
    for i, hit in enumerate(inc.strong):
        out.append(f"    => {'IEMESLS' if i == 0 else 'Arī'}: {hit.title}")
        out.append(f"       Kāpēc: {hit.why}")
        if hit.fix:
            out.append(f"       Ko darīt: {hit.fix}")
        out.append("       Žurnālā:")
        out.extend(f"         {_clip(e)}" for e in hit.evidence)
    for hit in inc.weak:
        out.append(f"    -- {'Iespējams iemesls' if not inc.strong else 'Iespējams saistīts'}: {hit.title}")
        if not inc.strong:
            out.append(f"       Kāpēc: {hit.why}")
            if hit.fix:
                out.append(f"       Ko darīt: {hit.fix}")
        out.extend(f"         {_clip(e)}" for e in hit.evidence[-2:])
    if not inc.strong:
        if not inc.weak:
            out.append("    Iemesls žurnālā nav skaidri redzams.")
        if inc.context:
            out.append("    Pēdējie saistītie ieraksti pirms izslēgšanās:")
            out.extend(f"         {_clip(c)}" for c in inc.context)
    return "\n".join(out)


def _headline(inc: Incident) -> str:
    if inc.strong:
        return inc.strong[0].title
    if inc.weak:
        return f"(iespējams) {inc.weak[0].title}"
    return "Nezināms iemesls"


def build_report(lines: Sequence[LogLine], snap: Dict[str, str]) -> str:
    props = parse_getprop(snap.get("getprop.txt", ""))
    uid_map = parse_packages(snap.get("packages.txt", ""))
    incidents = analyze_log(lines, uid_map)
    findings = check_snapshot(snap)
    out = ["=" * 72, "HOTSPOT DOCTOR — kāpēc izslēdzas hotspots", "=" * 72]

    if props:
        operator = props.get("gsm.sim.operator.alpha") or props.get("gsm.operator.alpha") or "?"
        out.append(f"Ierīce: {props.get('ro.product.manufacturer', '?')} {props.get('ro.product.model', '?')}, "
                   f"Android {props.get('ro.build.version.release', '?')} (SDK {_sdk(props) or '?'}), "
                   f"operators: {operator}")
    if lines:
        span = lines[-1][0] - lines[0][0]
        minutes = int(span.total_seconds() // 60)
        out.append(f"Žurnāls: {lines[0][0]:%Y-%m-%d %H:%M} … {lines[-1][0]:%Y-%m-%d %H:%M} "
                   f"(rindas: {len(lines)}, ~{minutes} min)")
        if minutes < 60:
            out.append("Piezīme: žurnāls aptver mazāk par stundu. Ja hotspots izslēdzās agrāk, tas šeit nav "
                       "redzams — palaid `watch` vai `fix` (palielina žurnāla buferi).")
    else:
        out.append("Žurnāls ir tukšs vai nav nolasāms.")

    out += ["", f"HOTSPOTA IZSLĒGŠANĀS GADĪJUMI: {len(incidents)}", "-" * 72]
    if not incidents:
        out.append("Žurnālā nav atrasts neviens hotspota izslēgšanās brīdis (iespējams, tas notika pirms "
                   "žurnāla sākuma). Ieslēdz hotspotu un palaid: python3 hotspot_doctor.py watch")
    else:
        for headline, n in Counter(_headline(i) for i in incidents).most_common():
            out.append(f"  {n}× {headline}")
        shown = incidents[-MAX_DETAILED_INCIDENTS:]
        if len(shown) < len(incidents):
            out.append(f"  (sīkāk parādīti pēdējie {len(shown)})")
        first = len(incidents) - len(shown) + 1
        for i, inc in enumerate(shown, first):
            out += ["", render_incident(inc, i)]

    out += ["", "TELEFONA IESTATĪJUMI", "-" * 72]
    if not findings:
        out.append("Nekas aizdomīgs iestatījumos netika atrasts." if snap else
                   "Iestatījumi netika savākti (analizēts tikai žurnāls).")
    for f in findings:
        out.append(f"[{f.level}] {f.title}")
        if f.detail:
            out.append(f"    {f.detail}")
        if f.fix and f.level == "!":
            out.append(f"    Ko darīt: {f.fix}")

    fix_counts = Counter(h.fix for i in incidents for h in i.strong if h.fix)
    fixes = [fx for fx, _ in fix_counts.most_common()]
    extra = [f.fix for f in findings if f.level == "!" and f.fix]
    extra += [i.weak[0].fix for i in incidents if not i.strong and i.weak and i.weak[0].fix]
    for fx in extra:
        if fx not in fixes:
            fixes.append(fx)

    out += ["", "KO DARĪT", "-" * 72]
    if fixes:
        out.extend(f"{n}. {fx}" for n, fx in enumerate(fixes, 1))
    else:
        out.append("1. Palaid `python3 hotspot_doctor.py fix` (palielina žurnāla buferi), ieslēdz hotspotu un "
                   "`python3 hotspot_doctor.py watch` — nākamajā izslēgšanās reizē rīks parādīs iemeslu.")
    entitlement_lines = sum(1 for _, text in lines if re.search(r"EntitlementManager|entitlement", text, re.I))
    out += ["", SERVERS_NOTE,
            f"Operatora atļaujas pārbaudes ieraksti šajā žurnālā: {entitlement_lines}."]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# ADB
# ---------------------------------------------------------------------------

class AdbError(Exception):
    pass


ADB_MISSING = (
    "Nav atrasts `adb`. Lejupielādē Android SDK Platform-Tools: "
    "https://developer.android.com/tools/releases/platform-tools , atarhivē un norādi ceļu ar "
    "--adb CEĻŠ/adb (vai pievieno mapi PATH). Termux: pkg install android-tools"
)


class Adb:
    def __init__(self, path: str = "adb", serial: Optional[str] = None) -> None:
        self.base = [path] + (["-s", serial] if serial else [])

    def run(self, *args: str, timeout: Optional[float] = 60) -> Tuple[int, str]:
        try:
            proc = subprocess.run(self.base + list(args), stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        except FileNotFoundError as exc:
            raise AdbError(ADB_MISSING) from exc
        except subprocess.TimeoutExpired as exc:
            return 124, (exc.stdout or b"").decode("utf-8", "replace")
        return proc.returncode, proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n")

    def shell(self, command: str, timeout: Optional[float] = 60) -> Tuple[int, str]:
        return self.run("shell", command, timeout=timeout)

    def popen(self, *args: str) -> subprocess.Popen:
        try:
            return subprocess.Popen(self.base + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except FileNotFoundError as exc:
            raise AdbError(ADB_MISSING) from exc

    def require_device(self) -> None:
        rc, out = self.run("get-state", timeout=20)
        state = out.strip()
        if rc == 0 and state == "device":
            return
        if "more than one" in state:
            raise AdbError("Pieslēgtas vairākas ierīces — norādi vienu ar --serial (sk. `adb devices`).")
        if "unauthorized" in state:
            raise AdbError("Telefons nav atļāvis atkļūdošanu: atbloķē ekrānu un apstiprini «Atļaut USB "
                           "atkļūdošanu?» logu, tad mēģini vēlreiz.")
        raise AdbError("Telefons nav atrasts. Pieslēdz to ar USB, ieslēdz Izstrādātāja opcijas -> «USB "
                       "atkļūdošana» un pārbaudi ar `adb devices`. (adb: " + (state or f"kods {rc}") + ")")


LOGCAT_VARIANTS = [
    ["-v", "threadtime", "-v", "year", "-b", "all"],
    ["-v", "threadtime", "-b", "all"],
    ["-v", "threadtime", "-b", "main", "-b", "system", "-b", "events", "-b", "radio", "-b", "crash"],
    ["-v", "threadtime"],
]
LOGCAT_ERROR_RE = re.compile(r"^(?:logcat: |unknown buffer|invalid |usage: logcat)", re.I | re.M)


def pick_logcat_args(adb: Adb) -> List[str]:
    for variant in LOGCAT_VARIANTS:
        rc, out = adb.run("logcat", "-d", "-t", "1", *variant, timeout=30)
        if rc == 0 and not LOGCAT_ERROR_RE.search(out):
            return variant
    return LOGCAT_VARIANTS[-1]


SNAPSHOT_COMMANDS = [
    # (file, shell command, timeout, only for SDK below this value)
    ("getprop.txt", "getprop", 30, None),
    ("settings_global.txt", "settings list global", 30, None),
    ("settings_system.txt", "settings list system", 30, None),
    ("netpolicy.txt", "cmd netpolicy get restrict-background", 30, None),
    ("packages.txt", "pm list packages -U", 60, None),
    ("dumpsys_wifi.txt", "dumpsys wifi", 120, None),
    ("dumpsys_tethering.txt", "dumpsys tethering", 60, None),
    ("dumpsys_connectivity_tethering.txt", "dumpsys connectivity tethering", 60, 30),
    ("dumpsys_carrier_config.txt", "dumpsys carrier_config", 60, None),
    ("dumpsys_thermalservice.txt", "dumpsys thermalservice", 30, None),
]
SNAPSHOT_FILES = [name for name, *_ in SNAPSHOT_COMMANDS]


def collect_snapshot(adb: Adb, out_dir: Path) -> Dict[str, str]:
    snap: Dict[str, str] = {}
    sdk = 0
    for name, command, timeout, below_sdk in SNAPSHOT_COMMANDS:
        if below_sdk is not None and sdk >= below_sdk:
            continue
        print(f"  … {command}")
        _, text = adb.shell(command, timeout=timeout)
        snap[name] = text
        (out_dir / name).write_text(text, encoding="utf-8")
        if name == "getprop.txt":
            sdk = _sdk(parse_getprop(text))
    return snap


def load_snapshot(folder: Path) -> Dict[str, str]:
    return {name: (folder / name).read_text(encoding="utf-8", errors="replace")
            for name in SNAPSHOT_FILES if (folder / name).is_file()}


def new_out_dir(base: Optional[str], prefix: str) -> Path:
    path = Path(base or ".") / f"{prefix}-{dt.datetime.now():%Y%m%d-%H%M%S}"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_diagnose(args: argparse.Namespace) -> int:
    adb = Adb(args.adb, args.serial)
    adb.require_device()
    out_dir = new_out_dir(args.out, "hotspot-report")
    print(f"Vācu datus no telefona -> {out_dir}")
    snap = collect_snapshot(adb, out_dir)
    print("  … logcat")
    _, log_text = adb.run("logcat", "-d", *pick_logcat_args(adb), timeout=300)
    (out_dir / "logcat.txt").write_text(log_text, encoding="utf-8")
    report = build_report(parse_log(log_text), snap)
    (out_dir / "report.txt").write_text(report, encoding="utf-8")
    print()
    print(report)
    print(f"Atskaite un visi savāktie dati: {out_dir}")
    print("Uzmanību: mapē ir telefona tehniskā informācija — nepublicē to atklāti.")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.is_dir():
        snap = load_snapshot(path)
        logs = [p for p in ("logcat.txt", "logcat-live.txt") if (path / p).is_file()]
        if not logs:
            print(f"Mapē {path} nav logcat.txt vai logcat-live.txt", file=sys.stderr)
            return 2
        log_text = "\n".join((path / p).read_text(encoding="utf-8", errors="replace") for p in logs)
    elif path.is_file():
        snap, log_text = {}, path.read_text(encoding="utf-8", errors="replace")
    else:
        print(f"Nav atrasts: {path}", file=sys.stderr)
        return 2
    print(build_report(parse_log(log_text, args.year), snap))
    return 0


class Watcher:
    """Consumes live logcat lines and reports each hotspot stop once its after-context has arrived."""

    def __init__(self, uid_map: Dict[int, List[str]], emit: Callable[[str], None],
                 year: Optional[int] = None) -> None:
        self.uid_map = uid_map
        self.emit = emit
        self.year = year or dt.date.today().year
        self.buf: deque = deque()
        self.pending: List[Tuple[dt.datetime, str, float]] = []
        self.last_stop: Optional[dt.datetime] = None
        self.count = 0

    def feed(self, text: str) -> None:
        ts = parse_ts(text, self.year)
        if ts is None:
            return
        self.buf.append((ts, text))
        while self.buf and self.buf[0][0] < ts - MAX_LOOKBACK - dt.timedelta(seconds=30):
            self.buf.popleft()
        if is_stop_line(text) and not (self.last_stop and ts - self.last_stop <= INCIDENT_GAP):
            self.last_stop = ts
            self.emit(f"\n>>> {ts:%H:%M:%S} hotspots izslēdzas — analizēju …")
            self.pending.append((ts, text, time.monotonic() + WATCH_WALL_WAIT))
        self.tick()

    def tick(self, force: bool = False) -> None:
        newest = self.buf[-1][0] if self.buf else None
        now = time.monotonic()
        for item in list(self.pending):
            t, trigger, due = item
            if force or now >= due or (newest is not None and newest >= t + CONTEXT_AFTER):
                self.pending.remove(item)
                self.count += 1
                lines = sorted(self.buf, key=lambda line: line[0])
                self.emit(render_incident(analyze_incident(lines, t, trigger, self.uid_map), self.count))


def _stream(adb: Adb, variant: List[str], watcher: Watcher, log_file) -> None:
    proc = adb.popen("logcat", "-T", "1", *variant)
    lines: "queue.Queue[Optional[str]]" = queue.Queue()

    def pump() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            lines.put(raw.decode("utf-8", "replace").rstrip("\r\n"))
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    try:
        while True:
            try:
                text = lines.get(timeout=1.0)
            except queue.Empty:
                watcher.tick()
                continue
            if text is None:
                return
            log_file.write(text + "\n")
            watcher.feed(text)
    finally:
        proc.terminate()
        log_file.flush()


def cmd_watch(args: argparse.Namespace) -> int:
    adb = Adb(args.adb, args.serial)
    adb.require_device()
    out_dir = new_out_dir(args.out, "hotspot-watch")
    print(f"Vācu telefona iestatījumus -> {out_dir}")
    snap = collect_snapshot(adb, out_dir)
    report_path = out_dir / "report.txt"

    def emit(text: str) -> None:
        print(text, flush=True)
        with report_path.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")

    for f in check_snapshot(snap):
        emit(f"[{f.level}] {f.title}" + (f" — {f.detail}" if f.detail else ""))
        if f.fix and f.level == "!":
            emit(f"    Ko darīt: {f.fix}")

    watcher = Watcher(parse_packages(snap.get("packages.txt", "")), emit)
    variant = pick_logcat_args(adb)
    print("\nUzraugu hotspotu. Ieslēdz to un atstāj telefonu pieslēgtu; kad tas izslēgsies, šeit parādīsies "
          "iemesls. Beigt: Ctrl+C\n", flush=True)
    with (out_dir / "logcat-live.txt").open("a", encoding="utf-8") as log_file:
        try:
            while True:
                _stream(adb, variant, watcher, log_file)
                watcher.tick(force=True)
                print("Savienojums ar telefonu pārtrūka — gaidu, kamēr to pieslēgs atkārtoti …", flush=True)
                adb.run("wait-for-device", timeout=None)
        except KeyboardInterrupt:
            watcher.tick(force=True)
    print(f"\nNoķertas izslēgšanās: {watcher.count}. Žurnāls un atskaite: {out_dir}")
    return 0


def _confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        print(f"{question} [j/N] j")
        return True
    try:
        answer = input(f"{question} [j/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("j", "ja", "jā", "y", "yes")


SHELL_ERROR_RE = re.compile(r"SecurityException|Permission denial|Exception|Error|not found|Unknown", re.I)


SOFTAP_TIMEOUT_OVERLAY = "config_wifiFrameworkSoftApShutDownTimeoutMilliseconds"
MAX_TIMEOUT_MS = 2**31 - 1  # ~24.8 days, the largest value the integer overlay accepts
HOTSPOT_SETTINGS_INTENTS = ("com.android.settings.WIFI_TETHER_SETTINGS", "android.settings.TETHER_SETTINGS")
XIAOMI_HINT = ("Xiaomi/Redmi/POCO: Izstrādātāja opcijas -> ieslēdz «USB atkļūdošana (Drošības iestatījumi)» "
               "un mēģini vēlreiz.")


@dataclass
class FixAction:
    description: str
    commands: List[List[str]]  # alternatives: the first one that succeeds is enough
    revert: str = ""
    fail_hint: str = ""
    done_note: str = ""


def _fix_actions(sdk: int, glob: Dict[str, str], data_saver: bool, disable_offload: bool) -> List[FixAction]:
    modern = sdk >= 30 or sdk == 0
    actions = [FixAction(
        f"Palielināt sistēmas žurnāla buferi līdz {LOG_BUFFER_SIZE}, lai iemesls nepazustu no žurnāla",
        [["logcat", "-G", LOG_BUFFER_SIZE]], "adb logcat -G 256K")]
    if 0 < sdk <= 29 and glob.get("soft_ap_timeout_enabled", "1") != "0":
        actions.append(FixAction(
            "Izslēgt hotspota automātisko izslēgšanos (soft_ap_timeout_enabled=0)",
            [["shell", "settings put global soft_ap_timeout_enabled 0"]],
            "adb shell settings put global soft_ap_timeout_enabled 1"))
    if sdk >= 36 or sdk == 0:
        # Android 11+ keeps the auto-off switch in the hotspot config, which adb cannot edit. The Android 16
        # Wi-Fi module lets the shell override the default idle timeout instead; it lasts until reboot.
        actions.append(FixAction(
            "Pagarināt hotspota automātiskās izslēgšanās taimautu līdz ~24 dienām "
            "(pēc telefona restarta jāatkārto)",
            [["shell", f"cmd wifi force-overlay-config-value integer {SOFTAP_TIMEOUT_OVERLAY} enabled "
                       f"{MAX_TIMEOUT_MS}"]],
            f"adb shell cmd wifi force-overlay-config-value integer {SOFTAP_TIMEOUT_OVERLAY} disabled",
            fail_hint="Šajā telefonā tas nav pieejams — izslēdz automātisko izslēgšanos iestatījumos (zemāk).",
            done_note="Stāsies spēkā pēc hotspota izslēgšanas un ieslēgšanas. Ja hotspotam iestatīts savs "
                      "taimauts (piem., Samsung), izslēdz slēdzi arī iestatījumos."))
    if data_saver:
        actions.append(FixAction(
            "Izslēgt datu taupīšanas režīmu (Data Saver), kas aptur hotspotu",
            [["shell", "cmd netpolicy set restrict-background false"]],
            "adb shell cmd netpolicy set restrict-background true"))
    if glob.get("low_power") == "1":
        actions.append(FixAction(
            "Izslēgt akumulatora taupīšanas režīmu",
            [["shell", "settings put global low_power 0"]], "adb shell settings put global low_power 1"))
    if glob.get("wifi_wakeup_enabled") == "1":
        actions.append(FixAction(
            "Izslēgt «Automātiski ieslēgt Wi-Fi» (Wi-Fi ieslēgšanās var noņemt hotspotu)",
            [["shell", "settings put global wifi_wakeup_enabled 0"]],
            "adb shell settings put global wifi_wakeup_enabled 1"))
    if disable_offload and glob.get("tether_offload_disabled") != "1":
        actions.append(FixAction(
            "Izslēgt «Piesaistes aparatūras paātrinājums» (tethering offload)",
            [["shell", "settings put global tether_offload_disabled 1"]],
            "adb shell settings put global tether_offload_disabled 0"))
    if modern:
        actions.append(FixAction(
            "Atvērt telefonā hotspota iestatījumus, lai izslēgtu «Automātiski izslēgt tīklāju»",
            [["shell", f"am start -a {action}"] for action in HOTSPOT_SETTINGS_INTENTS],
            fail_hint="Atver tos ar roku (ceļš zemāk).",
            done_note="Atbloķē telefonu un izslēdz slēdzi «Automātiski izslēgt tīklāju» / «Turn off hotspot "
                      "automatically» (Samsung: ⋮ -> Configure -> Advanced)."))
    return actions


def cmd_fix(args: argparse.Namespace) -> int:
    adb = Adb(args.adb, args.serial)
    adb.require_device()
    sdk = _sdk(parse_getprop(adb.shell("getprop", timeout=30)[1]))
    glob = parse_settings(adb.shell("settings list global", timeout=30)[1])
    data_saver = bool(re.search(r"\benabled\b", adb.shell("cmd netpolicy get restrict-background")[1], re.I))

    applied: List[str] = []
    for action in _fix_actions(sdk, glob, data_saver, args.disable_offload):
        if not _confirm(f"- {action.description}?", args.yes):
            continue
        for command in action.commands:
            rc, out = adb.run(*command, timeout=30)
            if rc == 0 and not SHELL_ERROR_RE.search(out):
                print("  Izdarīts." + (f" {action.done_note}" if action.done_note else ""))
                if action.revert:
                    applied.append(action.revert)
                break
        else:
            print(f"  NEIZDEVĀS: {_clip(out.strip(), 200) or f'kods {rc}'}")
            if action.fail_hint:
                print(f"  {action.fail_hint}")
            elif re.search(r"SecurityException|permission denial", out, re.I):
                print(f"  {XIAOMI_HINT}")

    print("\nPaliek izdarīt ar roku:")
    if sdk >= 30 or sdk == 0:
        print(f"- GALVENAIS: {AUTO_OFF_FIX}")
    print("- Hotspota iestatījumos izvēlies 2,4 GHz joslu (stabilāka, nav DFS radaru pārslēgšanās).")
    print("- Pārbaudi, vai pieslēgtā ierīce (dators) neaizmieg un neizslēdz Wi-Fi enerģijas taupīšanai.")
    print("- Pēc izmaiņām izslēdz un ieslēdz hotspotu no jauna.")
    if applied:
        print("\nJa gribi atcelt izmaiņas:")
        for revert in applied:
            print(f"  {revert}")
    print("\nTagad ieslēdz hotspotu un palaid `python3 hotspot_doctor.py watch`, lai noķertu iemeslu, ja tas "
          "atkal izslēdzas.")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    parser = argparse.ArgumentParser(
        prog="hotspot_doctor.py",
        description="Noskaidro, kāpēc Android telefonā izslēdzas hotspots, un palīdz to novērst.")
    parser.add_argument("--adb", default="adb", help="ceļš uz adb (noklusējums: adb no PATH)")
    parser.add_argument("--serial", "-s", help="ierīces sērijas numurs, ja pieslēgtas vairākas")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("diagnose", help="savākt datus un atrast iemeslus pēdējos žurnālos")
    p.add_argument("--out", help="mape, kurā saglabāt atskaiti (noklusējums: pašreizējā)")
    p.set_defaults(func=cmd_diagnose)

    p = sub.add_parser("watch", help="dzīvi uzraudzīt un noķert nākamo hotspota izslēgšanos")
    p.add_argument("--out", help="mape, kurā saglabāt žurnālu un atskaiti")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("fix", help="pielietot drošus labojumus (jautā pirms katra)")
    p.add_argument("--yes", "-y", action="store_true", help="nejautāt, pielietot visus")
    p.add_argument("--disable-offload", action="store_true",
                   help="izslēgt arī piesaistes aparatūras paātrinājumu (tethering offload)")
    p.set_defaults(func=cmd_fix)

    p = sub.add_parser("analyze", help="analizēt saglabātu atskaites mapi vai logcat failu")
    p.add_argument("path", help="hotspot-report-* / hotspot-watch-* mape vai logcat teksta fails")
    p.add_argument("--year", type=int, help="gads žurnāliem bez gada (noklusējums: šis gads)")
    p.set_defaults(func=cmd_analyze)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AdbError as exc:
        print(f"Kļūda: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
