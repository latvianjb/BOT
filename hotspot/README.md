# Hotspot Doctor — kāpēc telefonā izslēdzas hotspots

`hotspot_doctor.py` caur ADB nolasa Android telefona sistēmas žurnālu (logcat) un iestatījumus,
atrod **katru brīdi, kad hotspots izslēdzās**, un pasaka, **kas to izdarīja** (sistēmas taimauts,
operatora serveris, lietotne, Wi-Fi, pārkaršana u.c.) un **ko darīt**. Komanda `fix` pati
pielieto drošos labojumus.

## Kas izslēdz hotspotu

Hotspotu vienmēr izslēdz **pats telefons** (Android servisi `SoftApManager` un `Tethering`).
Biežākie iemesli, sākot ar biežāko:

| Iemesls | Kā to atpazīt | Labojums |
|---|---|---|
| **Automātiskā izslēgšanās, ja nav pieslēgtu ierīču** (parasti pēc 5–10 min; arī ja dators/TV aizmieg) | `SoftApManager: Timeout message received. Stopping soft AP.` | Izslēgt «Automātiski izslēgt tīklāju» / Samsung «Turn off when no device connected» → *Never* |
| **Ieslēdzās Wi-Fi** (ar roku, «Automātiski ieslēgt Wi-Fi», Samsung Intelligent Wi-Fi), un telefons neprot Wi-Fi + hotspotu vienlaikus | `setWifiEnabled … enable=true` tieši pirms izslēgšanās | `fix` izslēdz «Automātiski ieslēgt Wi-Fi» |
| **Operatora serveris neatļāva** (entitlement / provisioning pārbaude) | `EntitlementManager … failed`, `TETHER_ERROR_PROVISIONING_FAILED` | Jautāt operatoram, vai tarifā atļauta koplietošana; atiestatīt APN |
| **Lietotne** (Tasker, rutīnas, MDM, «optimizētāji») | `stopSoftAp uid=…` / `stopTethering` ar lietotnes nosaukumu | Atslēgt automatizāciju vai atinstalēt lietotni |
| **Datu taupīšanas režīms** (Data Saver) | `onRestrictBackgroundChanged(true)` | `fix` to izslēdz |
| **Pārkaršana** | thermal / overheat ieraksti | Noņemt vāciņu, nelādēt ar ātro lādētāju, 2,4 GHz josla |
| **Pazūd mobilais internets** (vājš signāls, 4G↔5G, datu limits) | `UpstreamNetworkMonitor … onLost` | Iestatīt 4G/LTE, pārbaudīt datu limitu |
| **Akumulatora taupīšana, Wi-Fi draivera kļūda, 5 GHz DFS radars, aparatūras paātrinājums** | hostapd / DFS / offload kļūdas | 2,4 GHz josla, atjauninājumi, `fix --disable-offload` |

### Kādi serveri?

Interneta serveri, ar kuriem sazinās telefona lietotnes, hotspotu izslēgt **nevar**. Vienīgais ārējais
serveris, kas to var ietekmēt, ir **operatora atļaujas (entitlement) pārbaudes serveris**: daļa
operatoru liek telefonam, ieslēdzot hotspotu un periodiski arī vēlāk, pārbaudīt, vai tarifs atļauj
koplietot internetu. Ja pārbaude neizdodas vai serveris neatbild, Android hotspotu izslēdz. Rīks
parāda, vai jūsu operators šo pārbaudi pieprasa un vai tā ir neizdevusies.

Operators var arī pamanīt koplietošanu pēc pakešu TTL un ierobežot ātrumu. Tad hotspots paliek
ieslēgts, bet pieslēgtajām ierīcēm pazūd vai palēninās internets.

## Lietošana

Vajag datoru ar **Python 3.8+** un **Android Platform-Tools (`adb`)**:
<https://developer.android.com/tools/releases/platform-tools>

1. Telefonā: *Iestatījumi → Par tālruni* → 7× pieskarties **Būvējuma numurs** → *Izstrādātāja opcijas*
   → ieslēgt **USB atkļūdošana**.
2. Pieslēgt telefonu ar USB un apstiprināt logu «Atļaut USB atkļūdošanu?».
3. Palaist:

```bash
python3 hotspot_doctor.py diagnose   # analizē pēdējos žurnālus + iestatījumus
python3 hotspot_doctor.py fix        # droši labojumi, jautā pirms katra (-y = visi)
python3 hotspot_doctor.py watch      # ieslēdz hotspotu un gaidi: noķer nākamo izslēgšanos
```

Windows: `py hotspot_doctor.py diagnose`; ja `adb` nav PATH, norādi ceļu:
`py hotspot_doctor.py --adb C:\platform-tools\adb.exe diagnose`.
Ja pieslēgti vairāki telefoni: `--serial SĒRIJAS_NR` (sk. `adb devices`).

Telefona žurnāls glabā tikai pēdējās minūtes vai stundas. Tāpēc, ja `diagnose` neko neatrod,
palaid `fix` (tas palielina žurnāla buferi līdz 16 MB) un tad `watch`, un atstāj to darboties,
līdz hotspots atkal izslēdzas.

`analyze MAPE` atkārtoti analizē saglabātu `hotspot-report-*` / `hotspot-watch-*` mapi vai jebkuru
logcat teksta failu.

### Ko maina `fix`

| Izmaiņa | Kad | Atcelt |
|---|---|---|
| Žurnāla buferis 16 MB | vienmēr | `adb logcat -G 256K` |
| `soft_ap_timeout_enabled=0` (automātiskā izslēgšanās) | Android 10 un vecāks | `adb shell settings put global soft_ap_timeout_enabled 1` |
| Data Saver izslēgts | ja ieslēgts | `adb shell cmd netpolicy set restrict-background true` |
| Akumulatora taupīšana izslēgta | ja ieslēgta | `adb shell settings put global low_power 1` |
| «Automātiski ieslēgt Wi-Fi» izslēgts | ja ieslēgts | `adb shell settings put global wifi_wakeup_enabled 1` |
| Piesaistes aparatūras paātrinājums izslēgts | tikai ar `--disable-offload` | `adb shell settings put global tether_offload_disabled 0` |

Android 11 un jaunākā versijā automātiskās izslēgšanās slēdzis glabājas hotspota konfigurācijā, un
ADB to mainīt nevar. Tā vietā `fix` parāda, kur to izslēgt iestatījumos. Rīks **neapiet**
operatora ierobežojumus.

Privātums: atskaites mapē ir telefona tehniskā informācija (modelis, iestatījumi, žurnāls) — nepublicē
to atklāti.

## Testi

```bash
python3 -m unittest discover -s tests -v
```
