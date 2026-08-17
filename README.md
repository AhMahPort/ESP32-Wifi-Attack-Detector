# ESP32 WiFi Attack Detector (WIDS)

**A pocket-sized wireless intrusion detection system that spots WiFi attacks the moment they happen, built from scratch on a $20 microcontroller, in C, from raw 802.11 frames up.**

This parses the wireless management frames directly, decides what's an attack and what's just noise, and prints a live alert the instant something's wrong. It is strictly a **detector** - it listens, it never transmits.

To prove it actually works, the detector was validated against **real attacks generated on a controlled lab network** using a Flipper Zero with an ESP32 WiFi dev board running the Marauder firmware and an Arduino Nano ESP32-S3 microcontroller. Red team on one bench, blue team on the other.

---

## Highlights

- **Four attack detections** running in real time: deauth floods, evil-twin APs, weak-security networks, and beacon floods
- **Written from the frame up in C** - direct 802.11 parsing, no black-box libraries doing the work
- **Validated against live attacks** - a Flipper Zero + ESP32/Marauder rig generated real deauth and rogue-AP traffic that the detector caught
- **Analyst-grade interpretation** - distinguishes a real evil twin from a harmless dual-band router (see *Not Every Alert Is an Attack* below)
- **Defensive by design** - passive monitoring only, all testing on a self-owned, isolated lab network

> **Authorized use only.** The detector passively monitors 802.11 management frames. The attack-generation rig (Marauder) was used solely against a network the operator owns, to validate detection. Nothing here targets third-party networks.

---

## What It Detects

| Detection | Signature | Alert |
|---|---|---|
| **Deauth flood** | Spike in deauth (0x0C) / disassoc (0x0A) frames per window | Attack in progress |
| **Evil twin / rogue AP** | Same SSID advertised by a new, unexpected BSSID | Possible impersonation |
| **Weak security** | Beacon advertises Open / WEP / WPA1 | Insecure network |
| **Beacon flood** | Abnormal volume of beacon frames per window | Beacon-spam tool |

---

## The Lab Rig

Detection is only convincing if you can prove it fires on a real attack. This project uses a two-sided bench; an attacker and a detector, both on hardware the operator owns, on an isolated network.

**Attack side (red team):**
- **Flipper Zero** running the **Marauder** app as the controller/interface
- **ESP32-S2 WiFi dev board** flashed with **Marauder firmware** as the radio
- Used to generate controlled test traffic against the operator's own test AP: deauthentication frames, beacon spam, and rogue/duplicate APs

**Detector side (blue team):**
- **ESP32** running this project's `wids.ino`, in passive monitor mode
- Watches the same channel and raises alerts when the Marauder-generated attacks appear

The Marauder rig's only job here is to produce known, repeatable attack traffic so the detector's alerts can be verified against ground truth. Everything happens on a self-owned lab network.

---

## See It Work

Healthy baseline - capturing ~150 management frames per 10-second window, nothing hostile:

```
[stat] mgmt=163 beacons=149 total_deauth=0 weak_aps=1 ch=2
```

The moment an evil twin appears - same network name, different radio:

```
----------------------------------------------
[!!!] POSSIBLE EVIL TWIN   (ch 2)
      SSID: "REDACTED"
      seen from BSSID: XX:XX:XX:XX:XX:33
      NOW also from  : XX:XX:XX:XX:XX:BF
----------------------------------------------
```

An open, unencrypted network on the air:

```
----------------------------------------------
[!] WEAK SECURITY NETWORK   (ch 2)
    SSID : "REDACTED"
    BSSID: XX:XX:XX:XX:XX:XX
    Security: OPEN (no encryption)
----------------------------------------------
```

## How It Works

The ESP32 runs in promiscuous (monitor) mode, watching raw 802.11 frames without joining any network. A single fast callback parses each management frame and feeds four detection routines:

```
ESP32 (monitor mode, 2.4 GHz)
  -> parse 802.11 mgmt frames
  -> deauth / disassoc counter   (time-windowed)     -> deauth-flood alert
  -> SSID -> BSSID map             (per beacon)        -> evil-twin alert
  -> beacon security parse         (capability + IEs)  -> weak-security flag
  -> beacon rate counter           (time-windowed)     -> beacon-flood alert
  -> alerts printed over USB serial (115200 baud)
```

Detections are flagged inside the capture callback and printed from the main loop, keeping the time-critical sniffer path fast so it never drops frames.

---

## Detection Logic

- **Deauth flood** - counts deauthentication and disassociation frames per one-second window and alerts past a threshold. Legitimate networks send almost none, so a spike is a strong signal.
- **Evil twin** - maintains a live `SSID -> set of BSSIDs` map from beacons. A known SSID surfacing from a new, unexpected BSSID is flagged as a possible rogue AP.
- **Weak security** - parses each beacon's capability field and RSN / vendor information elements, classifies the network as Open, WEP, WPA1, or WPA2/WPA3, and flags anything weaker than WPA2 (once per BSSID).
- **Beacon flood** - tracks beacon rate per window; a surge past threshold indicates beacon-spam tooling.

---

## Not Every Alert Is an Attack

The most valuable lesson from building this: **raw detections are signals, not verdicts.**

During live testing the detector flagged an evil-twin event; one SSID broadcasting from two BSSIDs. But the two MAC addresses shared the same OUI (manufacturer prefix) and differed only in their final bytes. That is the fingerprint of a single dual-band router advertising the same name on 2.4 GHz and 5 GHz, not a rogue device. A genuine evil twin almost always presents a completely different MAC and OUI.

This is exactly why production WIDS platforms rely on **whitelisting and correlation** instead of trusting every duplicate. Reading an alert in context, telling signal from noise; is the analyst skill this project is really about.

**Planned improvement (Stage 6):** downgrade duplicate-SSID events to informational when the BSSIDs share an OUI and are numerically adjacent (likely dual-band), and reserve full alerts for a genuinely different OUI.

---

## Attacks and Their Defenses

Every attack this detects has a corresponding defense - the blue-team half of the story:

| Attack | Defense |
|---|---|
| **Deauth flood** | 802.11w Protected Management Frames (PMF), mandatory in WPA3 - encrypted management frames make deauth spoofing fail |
| **Evil twin** | WPA3-Enterprise / 802.1X certificate validation; user awareness |
| **Weak crypto** | Migrate Open / WEP / WPA1 to WPA2 / WPA3 |
| **Beacon flood** | Client-side AP validation; WIDS alerting on beacon anomalies |

---

## Build Stages

Built incrementally, validating each capability against the Marauder rig before adding the next:

- [x] **Stage 1** - Monitor mode + parse all 802.11 management frame types
- [x] **Stage 2** - Deauth / disassoc flood detection
- [x] **Stage 3** - Evil-twin detection (SSID -> BSSID mapping)
- [x] **Stage 4** - Weak-security flagging + beacon-flood detection
- [ ] **Stage 5** - Standalone display (OLED / Flipper Zero companion app)
- [ ] **Stage 6** - BSSID-similarity filtering to cut dual-band false positives

---

## Getting Started

**Detector hardware:** any ESP32 (developed and tested on an ESP32-S2-WROVER).
**Software:** Arduino IDE with ESP32 board support.

1. Open `wids.ino` in the Arduino IDE.
2. Select your ESP32 board. On the ESP32-S2, set **USB CDC On Boot -> Enabled** so serial output works over native USB.
3. Set the target channel: edit `LOCK_CHANNEL` to your network's channel, or set `CHANNEL_HOP true` to scan all channels.
4. Upload, then open the Serial Monitor at **115200 baud**.

The detector immediately begins cataloging nearby networks, printing periodic `[stat]` lines, and raising alerts as events occur.

---

## Test Methodology (Isolated Lab)

All validation was performed on a self-owned test network, using the Flipper Zero + ESP32/Marauder rig as the controlled attack source:

- **Deauth:** launch a deauth against my own test AP from the Marauder rig -> detector fires `DEAUTH FLOOD DETECTED`.
- **Evil twin:** broadcast a second AP (Marauder rogue-AP / spare router / hotspot) using my test network's SSID -> detector fires `POSSIBLE EVIL TWIN`.
- **Weak security:** set a test AP to Open / WPA1 -> detector flags it.
- **Beacon flood:** run beacon spam from the Marauder rig -> detector fires `BEACON FLOOD DETECTED`.
- **Defense demo:** enable WPA3 / 802.11w (PMF) on the test AP -> re-run the deauth -> attack fails, demonstrating the mitigation.

Detector and attacker are separate radios; both are owned by the operator, on an isolated network.

---

## Engineering Notes

A few problems solved along the way, documented because the debugging is the skill:

- **ESP32-S2 native-USB flashing** - required manual bootloader entry (hold BOOT, tap RESET) and a WebSerial-capable browser; resolved the driver and port issues specific to the S2's native USB.
- **Promiscuous mode capturing zero frames** - fixed by explicitly initializing the WiFi driver (`esp_wifi_init` -> `esp_wifi_start` -> `esp_wifi_set_promiscuous`) before enabling monitor mode, rather than relying on the higher-level mode call.
- **Frame-safe alerting** - detections are flagged in the callback and printed from the main loop to avoid dropping frames or blocking the capture path.

---

## Skills Demonstrated

`802.11 / WiFi security` &middot; `Wireless Intrusion Detection (WIDS)` &middot; `Embedded C / Arduino` &middot; `ESP32` &middot; `Packet analysis` &middot; `Frame parsing` &middot; `Red-team vs blue-team validation` &middot; `Defensive security` &middot; `Alert correlation`

---

Built by **Ahmed Mahmoud** - Identity & Access Management / Security
[GitHub](https://github.com/AhMahPort) &middot; [LinkedIn](https://www.linkedin.com/in/ahmed-netsec-mahmoud/)

_For authorized, defensive use on networks you own or have written permission to monitor._
