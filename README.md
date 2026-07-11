# 📡 ESP32 WiFi Attack Detector (WIDS)

A lightweight **Wireless Intrusion Detection System** built from scratch on the ESP32. It listens to 802.11 management frames in monitor mode and detects common WiFi attacks in real time — **deauthentication floods, evil-twin access points, and beacon floods** — and flags **weak-security networks** (Open / WEP / WPA1).

Built as a **defensive** security project: it detects attacks, it does not perform them. All frames are captured passively; the device never transmits.

![Platform](https://img.shields.io/badge/Platform-ESP32-000000)
![Type](https://img.shields.io/badge/Type-WIDS%20%2F%20Defensive-0C5F36)
![Language](https://img.shields.io/badge/Language-C%20%2F%20Arduino-blue)
![Status](https://img.shields.io/badge/Status-Working-brightgreen)

> ⚠️ **Authorized use only.** This tool passively monitors 802.11 management frames. All testing shown here was performed on an **isolated lab network I own and control**. It is a detection tool and does not transmit attacks.

---

## 🎯 What It Detects

| Detection | Signature | Alert |
|---|---|---|
| **Deauth flood** | Spike in deauth (0x0C) / disassoc (0x0A) frames per window | 🔴 Attack in progress |
| **Evil twin / rogue AP** | Same SSID advertised by a new/unexpected BSSID | 🔴 Possible impersonation |
| **Weak security** | Beacon advertises Open / WEP / WPA1 | 🟡 Insecure network |
| **Beacon flood** | Abnormal volume of beacon frames per window | 🔴 Beacon-spam tool |

---

## 🏗️ How It Works

The ESP32 runs in **promiscuous (monitor) mode**, observing raw 802.11 frames without associating to any network. A frame handler parses management frames and feeds four detection routines:

```
ESP32 (monitor mode, 2.4 GHz)
  -> parse 802.11 mgmt frames
  -> deauth / disassoc counter   (time-windowed)     -> deauth-flood alert
  -> SSID -> BSSID map             (per beacon)        -> evil-twin alert
  -> beacon security parse         (capability + IEs)  -> weak-security flag
  -> beacon rate counter           (time-windowed)     -> beacon-flood alert
  -> alerts printed over USB serial (115200 baud)
```

Alerts are queued in the frame callback and printed from the main loop, so the time-critical sniffer path stays fast and never drops frames.

---

## 📟 Sample Output (redacted)

Healthy baseline — capturing ~150 management frames per 10-second window, no attacks:

```
[stat] mgmt=163 beacons=149 total_deauth=0 weak_aps=1 ch=2
```

Evil-twin detection firing:

```
----------------------------------------------
[!!!] POSSIBLE EVIL TWIN   (ch 2)
      SSID: "REDACTED"
      seen from BSSID: XX:XX:XX:XX:XX:33
      NOW also from  : XX:XX:XX:XX:XX:BF
----------------------------------------------
```

Weak-security flagging firing:

```
----------------------------------------------
[!] WEAK SECURITY NETWORK   (ch 2)
    SSID : "REDACTED"
    BSSID: XX:XX:XX:XX:XX:XX
    Security: OPEN (no encryption)
----------------------------------------------
```

> 🖼️ _Demo video / screen recording of live alerts goes here._

---

## 🔍 Detection Logic (detail)

- **Deauth flood** — counts deauthentication + disassociation frames per 1-second window; alerts when the count crosses a threshold. Legitimate networks send very few of these, so a spike is a strong attack signal.
- **Evil twin** — maintains a map of `SSID -> set of BSSIDs` from beacons. A known SSID appearing under a **new, unexpected BSSID** is flagged as a possible rogue AP.
- **Weak security** — parses each beacon's capability field and RSN/vendor information elements to classify the network as Open, WEP, WPA1, or WPA2/WPA3, and flags anything weaker than WPA2 (once per BSSID).
- **Beacon flood** — tracks beacon rate per window; a surge past threshold indicates beacon-spam tooling.

---

## 🧠 Analyst Notes: Not Every Alert Is an Attack

A key lesson from building this: **raw detections are signals, not verdicts** — they require correlation.

Example from live testing: the detector flagged an evil-twin event for one SSID appearing from two BSSIDs. On inspection, the two MACs shared the same OUI (manufacturer prefix) and differed only in the final bytes — the signature of **one physical dual-band router** broadcasting the same SSID on 2.4 GHz and 5 GHz, **not** a rogue device. A genuine evil twin would typically present a completely different MAC/OUI.

This is exactly why production WIDS tools use **BSSID whitelisting and correlation** rather than treating every duplicate as hostile. Interpreting alerts in context — separating signal from noise — is the analyst skill this project surfaces.

**Planned improvement:** downgrade duplicate-SSID events to informational when the BSSIDs share an OUI and are numerically adjacent (likely dual-band), and reserve full alerts for BSSIDs with a different OUI (more suspicious).

---

## 🛡️ Attacks and Their Defenses

For each attack this detects, the corresponding defense — the blue-team half of the story:

| Attack | Defense |
|---|---|
| **Deauth flood** | 802.11w Protected Management Frames (PMF), mandatory in WPA3 — encrypted mgmt frames make deauth spoofing fail |
| **Evil twin** | WPA3-Enterprise / 802.1X certificate validation; user awareness |
| **Weak crypto** | Migrate Open / WEP / WPA1 to WPA2 / WPA3 |
| **Beacon flood** | Client-side AP validation; WIDS alerting on beacon anomalies |

---

## 🧰 Build Stages

The detector was built incrementally, validating each capability before adding the next:

- [x] **Stage 1** — Monitor mode + parse all 802.11 management frame types
- [x] **Stage 2** — Deauth / disassoc flood detection
- [x] **Stage 3** — Evil-twin detection (SSID -> BSSID mapping)
- [x] **Stage 4** — Weak-security flagging + beacon-flood detection
- [ ] **Stage 5** — Standalone display (OLED / Flipper Zero companion app)
- [ ] **Stage 6** — BSSID-similarity filtering to reduce dual-band false positives

---

## 🚀 Getting Started

**Hardware:** any ESP32 (developed and tested on an ESP32-S2-WROVER).
**Software:** Arduino IDE with ESP32 board support.

1. Open `wids.ino` in the Arduino IDE.
2. Select your ESP32 board. On the ESP32-S2, set **USB CDC On Boot -> Enabled** so serial output works over native USB.
3. Set the target channel: edit `LOCK_CHANNEL` to your network's channel (or set `CHANNEL_HOP true` to scan all channels).
4. Upload, then open the Serial Monitor at **115200 baud**.

You'll see the detector begin cataloging nearby networks and printing periodic `[stat]` lines, with alerts as events occur.

---

## 🧪 Test Methodology (isolated lab)

All validation was performed on a **self-owned test network** with my own devices:

- **Deauth:** run a deauth against my own test AP from a separate board -> detector fires `DEAUTH FLOOD DETECTED`.
- **Evil twin:** broadcast a second AP (spare router / hotspot) using my test network's SSID -> detector fires `POSSIBLE EVIL TWIN`.
- **Weak security:** set a test AP to Open / WPA1 -> detector flags it.
- **Defense demo:** enable WPA3 / 802.11w (PMF) on the test AP -> re-run the deauth -> attack fails, demonstrating the mitigation.

---

## 🧩 Engineering Notes

A few problems solved along the way (documented because the debugging *is* the skill):

- **ESP32-S2 native-USB flashing** — required manual bootloader entry (hold BOOT, tap RESET) and a WebSerial-capable browser; resolved the driver/port issues specific to the S2.
- **Promiscuous mode capturing zero frames** — fixed by explicitly initializing the WiFi driver (`esp_wifi_init` -> `esp_wifi_start` -> `esp_wifi_set_promiscuous`) before enabling monitor mode, rather than relying on the higher-level mode call.
- **Frame-safe alerting** — detections are flagged in the callback and printed from the main loop to avoid dropping frames or blocking in the capture path.

---

## 🧠 Skills Demonstrated

`802.11 / WiFi security` · `Wireless Intrusion Detection (WIDS)` · `Embedded C / Arduino` · `ESP32` · `Packet analysis` · `Frame parsing` · `Defensive security` · `Alert correlation`

---

> Built by **Ahmed Mahmoud** — Identity & Access Management / Security
> [GitHub](https://github.com/AhMahPort) · [LinkedIn](https://www.linkedin.com/in/ahmed-netsec-mahmoud/)
>
> _For authorized, defensive use on networks you own or have written permission to monitor._
