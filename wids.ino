/*
 * ESP32 WiFi Attack Detector  -  Stage 1 + 2 + 3 + 4
 * ------------------------------------------------------------
 * Stage 1: monitor (promiscuous) mode + parse 802.11 mgmt frames.
 * Stage 2: detect deauthentication / disassociation floods.
 * Stage 3: detect evil-twin APs (same SSID from a new BSSID).
 * Stage 4: flag weak-security networks (Open/WEP/WPA1) + beacon floods.
 *
 * DEFENSIVE + PASSIVE: this sketch only LISTENS. It never transmits
 * attacks. Use it on a network you own or are authorized to monitor.
 *
 * Author: Ahmed Mahmoud
 */

#include <WiFi.h>
#include "esp_wifi.h"
#include <string.h>

// ------------------------- CONFIG -------------------------
#define DETECT_WINDOW_MS       1000   // deauth + beacon-flood evaluation window
#define DEAUTH_THRESHOLD       5      // deauth+disassoc per window => ALERT
#define BEACON_FLOOD_THRESHOLD 150    // beacons per window => flood ALERT (tune)
#define STATS_EVERY_MS         10000  // heartbeat stats interval

#define CHANNEL_HOP        false  // true = scan all channels
                                  // false = lock to LOCK_CHANNEL (best for a demo)
#define LOCK_CHANNEL       2      // your test AP's channel when CHANNEL_HOP=false
#define MAX_CHANNEL        11     // US = 11, most of EU = 13
#define HOP_INTERVAL_MS    250    // dwell time per channel when hopping

#define MAX_TRACKED   40   // distinct SSIDs remembered (evil-twin)
#define MAX_BSSID_PER 4    // BSSIDs tolerated per SSID (mesh/dual-band)
#define MAX_WEAK      40   // weak APs remembered (dedup)

// --------------------- 802.11 HEADER ----------------------
typedef struct {
  uint8_t  frame_ctrl_0;
  uint8_t  frame_ctrl_1;
  uint16_t duration;
  uint8_t  addr1[6];       // destination / target
  uint8_t  addr2[6];       // source / transmitter
  uint8_t  addr3[6];       // BSSID
  uint16_t seq_ctrl;
} __attribute__((packed)) wifi_mgmt_hdr_t;

enum SecLevel { SEC_OPEN, SEC_WEP, SEC_WPA1, SEC_WPA2_3 };

// ----------------------- COUNTERS -------------------------
volatile uint32_t deauth_count   = 0;
volatile uint32_t disassoc_count = 0;
volatile uint32_t beacon_count   = 0;   // for stats
volatile uint32_t beacon_window  = 0;   // for flood detection
volatile uint32_t mgmt_count     = 0;

volatile uint8_t  last_attacker[6] = {0};
volatile uint8_t  last_target[6]   = {0};

unsigned long window_start = 0;
unsigned long stats_timer  = 0;
unsigned long hop_timer    = 0;
uint8_t current_channel    = 1;
uint32_t total_deauth = 0;

// ---------------- EVIL-TWIN STATE -------------------------
struct SsidEntry {
  char    ssid[33];
  uint8_t bssids[MAX_BSSID_PER][6];
  uint8_t bssid_count;
  bool    used;
};
SsidEntry tracked[MAX_TRACKED];

volatile bool et_pending = false;
char    et_ssid[33];
uint8_t et_first_bssid[6];
uint8_t et_new_bssid[6];
uint8_t et_channel = 0;

// ---------------- WEAK-SECURITY STATE ---------------------
uint8_t weak_flagged[MAX_WEAK][6];
uint8_t weak_flagged_count = 0;

volatile bool weak_pending = false;
char     weak_ssid[33];
uint8_t  weak_bssid[6];
uint8_t  weak_channel = 0;
SecLevel weak_level = SEC_OPEN;

// ---------------------- HELPERS ---------------------------
static void mac_to_str(const volatile uint8_t* mac, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool mac_equal(const uint8_t* a, const uint8_t* b) {
  for(int i = 0; i < 6; i++) if(a[i] != b[i]) return false;
  return true;
}

static void set_channel(uint8_t ch) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  current_channel = ch;
}

// Classify a beacon's security by parsing capability + tagged IEs.
static SecLevel classify_security(const uint8_t* payload, int len) {
  if(len < 36) return SEC_WPA2_3;           // can't parse -> assume ok
  uint16_t cap = payload[34] | (payload[35] << 8);
  bool privacy = cap & 0x0010;              // Privacy bit
  if(!privacy) return SEC_OPEN;             // no encryption

  int i = 36;                               // tagged params start
  bool has_rsn = false, has_wpa = false;
  while(i + 2 <= len) {
    uint8_t tag  = payload[i];
    uint8_t tlen = payload[i + 1];
    if(i + 2 + tlen > len) break;
    if(tag == 0x30) {                       // RSN IE => WPA2/WPA3
      has_rsn = true;
    } else if(tag == 0xDD && tlen >= 4) {   // vendor IE: WPA1 = 00:50:F2:01
      if(payload[i+2]==0x00 && payload[i+3]==0x50 &&
         payload[i+4]==0xF2 && payload[i+5]==0x01) {
        has_wpa = true;
      }
    }
    i += 2 + tlen;
  }
  if(has_rsn) return SEC_WPA2_3;            // secure enough (not flagged)
  if(has_wpa) return SEC_WPA1;             // weak
  return SEC_WEP;                          // privacy set, no RSN/WPA => WEP
}

static bool already_weak_flagged(const uint8_t* bssid) {
  for(int i = 0; i < weak_flagged_count; i++)
    if(mac_equal(weak_flagged[i], bssid)) return true;
  return false;
}

// Record SSID->BSSID; flag evil-twin when a known SSID gains a new BSSID.
static void track_ssid(const char* ssid, const uint8_t* bssid, uint8_t channel) {
  if(ssid[0] == '\0') return;
  for(int i = 0; i < MAX_TRACKED; i++) {
    if(tracked[i].used && strcmp(tracked[i].ssid, ssid) == 0) {
      for(int b = 0; b < tracked[i].bssid_count; b++)
        if(mac_equal(tracked[i].bssids[b], bssid)) return;
      if(!et_pending) {
        strncpy(et_ssid, tracked[i].ssid, 32); et_ssid[32] = '\0';
        memcpy(et_first_bssid, tracked[i].bssids[0], 6);
        memcpy(et_new_bssid, bssid, 6);
        et_channel = channel;
        et_pending = true;
      }
      if(tracked[i].bssid_count < MAX_BSSID_PER) {
        memcpy(tracked[i].bssids[tracked[i].bssid_count], bssid, 6);
        tracked[i].bssid_count++;
      }
      return;
    }
  }
  for(int i = 0; i < MAX_TRACKED; i++) {
    if(!tracked[i].used) {
      tracked[i].used = true;
      strncpy(tracked[i].ssid, ssid, 32); tracked[i].ssid[32] = '\0';
      memcpy(tracked[i].bssids[0], bssid, 6);
      tracked[i].bssid_count = 1;
      return;
    }
  }
}

// ------------- PROMISCUOUS FRAME CALLBACK -----------------
void IRAM_ATTR sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if(type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;

  uint8_t fc      = payload[0];
  uint8_t ftype   = (fc >> 2) & 0x03;
  uint8_t subtype = (fc >> 4) & 0x0F;
  if(ftype != 0) return;

  mgmt_count++;
  const wifi_mgmt_hdr_t* hdr = (const wifi_mgmt_hdr_t*)payload;

  switch(subtype) {
    case 0x0C: // deauth
      deauth_count++;
      memcpy((void*)last_attacker, hdr->addr2, 6);
      memcpy((void*)last_target,   hdr->addr1, 6);
      break;
    case 0x0A: // disassoc
      disassoc_count++;
      memcpy((void*)last_attacker, hdr->addr2, 6);
      memcpy((void*)last_target,   hdr->addr1, 6);
      break;
    case 0x08: { // beacon
      beacon_count++;
      beacon_window++;

      // parse SSID (first tagged param after 24 hdr + 12 fixed)
      const int base = 24 + 12;
      char ssid[33]; ssid[0] = '\0';
      if(len >= base + 2) {
        const uint8_t* body = payload + base;
        if(body[0] == 0x00) {
          uint8_t ssid_len = body[1];
          if(ssid_len <= 32 && len >= base + 2 + ssid_len) {
            memcpy(ssid, &body[2], ssid_len);
            ssid[ssid_len] = '\0';
          }
        }
      }

      // evil-twin tracking
      if(ssid[0] != '\0') track_ssid(ssid, hdr->addr3, current_channel);

      // weak-security flagging (once per BSSID)
      SecLevel sec = classify_security(payload, len);
      if(sec != SEC_WPA2_3 && !already_weak_flagged(hdr->addr3)) {
        if(!weak_pending) {
          strncpy(weak_ssid, ssid, 32); weak_ssid[32] = '\0';
          memcpy(weak_bssid, hdr->addr3, 6);
          weak_channel = current_channel;
          weak_level = sec;
          weak_pending = true;
        }
        if(weak_flagged_count < MAX_WEAK) {
          memcpy(weak_flagged[weak_flagged_count], hdr->addr3, 6);
          weak_flagged_count++;
        }
      }
      break;
    }
    default:
      break;
  }
}

// ------------------------- SETUP --------------------------
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println();
  Serial.println("==============================================");
  Serial.println(" ESP32 WiFi Attack Detector  (Stage 1-4)");
  Serial.println(" Passive / defensive - listening only");
  Serial.println("==============================================");

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);

  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);

  if(CHANNEL_HOP) {
    set_channel(1);
    Serial.printf("Channel hopping 1..%d\n", MAX_CHANNEL);
  } else {
    set_channel(LOCK_CHANNEL);
    Serial.printf("Locked to channel %d\n", LOCK_CHANNEL);
  }
  Serial.printf("Deauth threshold : %d / %d ms\n", DEAUTH_THRESHOLD, DETECT_WINDOW_MS);
  Serial.printf("Beacon-flood thr : %d / %d ms\n", BEACON_FLOOD_THRESHOLD, DETECT_WINDOW_MS);
  Serial.println("Evil-twin + weak-security detection: ON\n");

  unsigned long now = millis();
  window_start = now;
  stats_timer  = now;
  hop_timer    = now;
}

// ------------------------- LOOP ---------------------------
void loop() {
  unsigned long now = millis();

  // evil-twin alert
  if(et_pending) {
    char first[18], nw[18];
    mac_to_str(et_first_bssid, first);
    mac_to_str(et_new_bssid,   nw);
    Serial.println("----------------------------------------------");
    Serial.printf ("[!!!] POSSIBLE EVIL TWIN   (ch %d)\n", et_channel);
    Serial.printf ("      SSID: \"%s\"\n", et_ssid);
    Serial.printf ("      seen from BSSID: %s\n", first);
    Serial.printf ("      NOW also from  : %s\n", nw);
    Serial.println("----------------------------------------------");
    et_pending = false;
  }

  // weak-security alert
  if(weak_pending) {
    char b[18]; mac_to_str(weak_bssid, b);
    const char* lvl = (weak_level == SEC_OPEN) ? "OPEN (no encryption)" :
                      (weak_level == SEC_WEP)  ? "WEP (broken)" :
                                                 "WPA1 (weak / deprecated)";
    Serial.println("----------------------------------------------");
    Serial.printf ("[!] WEAK SECURITY NETWORK   (ch %d)\n", weak_channel);
    Serial.printf ("    SSID : \"%s\"\n", weak_ssid);
    Serial.printf ("    BSSID: %s\n", b);
    Serial.printf ("    Security: %s\n", lvl);
    Serial.println("----------------------------------------------");
    weak_pending = false;
  }

  // channel hopping
  if(CHANNEL_HOP && (now - hop_timer >= HOP_INTERVAL_MS)) {
    uint8_t next = current_channel + 1;
    if(next > MAX_CHANNEL) next = 1;
    set_channel(next);
    hop_timer = now;
  }

  // deauth + beacon-flood detection window
  if(now - window_start >= DETECT_WINDOW_MS) {
    uint32_t d  = deauth_count;
    uint32_t da = disassoc_count;
    uint32_t hits = d + da;
    uint32_t bw = beacon_window;
    total_deauth += d;

    if(hits >= DEAUTH_THRESHOLD) {
      char atk[18], tgt[18];
      mac_to_str(last_attacker, atk);
      mac_to_str(last_target,   tgt);
      Serial.println("----------------------------------------------");
      Serial.printf ("[!!!] DEAUTH FLOOD DETECTED   (ch %d)\n", current_channel);
      Serial.printf ("      %lu deauth + %lu disassoc in %d ms\n",
                     (unsigned long)d, (unsigned long)da, DETECT_WINDOW_MS);
      Serial.printf ("      source (attacker): %s\n", atk);
      Serial.printf ("      target           : %s\n", tgt);
      Serial.println("----------------------------------------------");
    } else if(hits > 0) {
      Serial.printf("[.] %lu deauth/disassoc (below threshold, ch %d)\n",
                    (unsigned long)hits, current_channel);
    }

    if(bw >= BEACON_FLOOD_THRESHOLD) {
      Serial.println("----------------------------------------------");
      Serial.printf ("[!!!] BEACON FLOOD DETECTED   (ch %d)\n", current_channel);
      Serial.printf ("      %lu beacons in %d ms (threshold %d)\n",
                     (unsigned long)bw, DETECT_WINDOW_MS, BEACON_FLOOD_THRESHOLD);
      Serial.println("----------------------------------------------");
    }

    deauth_count   = 0;
    disassoc_count = 0;
    beacon_window  = 0;
    window_start   = now;
  }

  // periodic heartbeat
  if(now - stats_timer >= STATS_EVERY_MS) {
    Serial.printf("[stat] mgmt=%lu beacons=%lu total_deauth=%lu weak_aps=%d ch=%d\n",
                  (unsigned long)mgmt_count, (unsigned long)beacon_count,
                  (unsigned long)total_deauth, weak_flagged_count, current_channel);
    mgmt_count   = 0;
    beacon_count = 0;
    stats_timer  = now;
  }
}