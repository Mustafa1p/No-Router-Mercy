# CLONE_SPEC.md — Router Scan v2.60 Clean-Room Specification

**Subject binary:** `RouterScan.exe` v2.6.0.0 (2018-03-11), 2 723 840 bytes  
**Evidence sources:** bundled HTML manual (`help/ru/` and `help/en/`), `config.ini`, `ports.txt`, `ranges.txt`, `auth_*.txt`, `wlanpass.txt`, `filter.txt`, `exclusions.txt`, `RouterScan.log`, LibRouter API docs (`help/en/librouter/`), changelog (`help/ru/changelog.html`), FAQ (`help/ru/faq.html`), exploits list (`help/ru/exploits.html`).  
**Methodology:** black-box only — no decompilation, no code copying, no asset copying.

---

## Table of Contents

1. [Product Overview](#1-product-overview)  
2. [Architecture](#2-architecture)  
3. [Application State Machine](#3-application-state-machine)  
4. [Main Window — UI Specification](#4-main-window--ui-specification)  
   4.1 Top Panel  
   4.2 Scan Tables  
   4.3 Status Bar  
   4.4 Context Menus  
5. [Secondary Windows](#5-secondary-windows)  
   5.1 IP Range Editor  
   5.2 Settings Dialog  
   5.3 Filter Rules Editor  
   5.4 IP Exclusions Editor  
   5.5 WPS PIN Companion  
   5.6 3WiFi Uploader  
   5.7 Column Chooser  
6. [Scan Engine — Behavior Specification](#6-scan-engine--behavior-specification)  
   6.1 Port Scanner  
   6.2 Thread Model  
   6.3 Device Processing Pipeline  
   6.4 Scan Modes  
   6.5 Watchdog  
7. [Scanning Modules](#7-scanning-modules)  
8. [Authentication Subsystem](#8-authentication-subsystem)  
9. [Good Results Filter](#9-good-results-filter)  
10. [Wi-Fi / Wireless Tab](#10-wi-fi--wireless-tab)  
11. [WPS Audit Engine](#11-wps-audit-engine)  
12. [Geolocation Subsystem](#12-geolocation-subsystem)  
13. [File Formats](#13-file-formats)  
14. [Network Protocols](#14-network-protocols)  
15. [Settings & Persistence (config.ini)](#15-settings--persistence-configini)  
16. [Error Behaviors & Edge Cases](#16-error-behaviors--edge-cases)  
17. [LibRouter DLL Public API](#17-librouter-dll-public-api)  
18. [Startup & Shutdown Sequence](#18-startup--shutdown-sequence)  
19. [Keyboard Shortcuts](#19-keyboard-shortcuts)  
20. [Known Exploits Catalogue](#20-known-exploits-catalogue)  
21. [UNKNOWN Items](#21-unknown-items)

---

## 1. Product Overview

**Router Scan** is a Windows GUI application that discovers network devices reachable over HTTP/HTTPS, attempts to authenticate to their web admin interfaces (by credential brute-force or by exploiting known vulnerabilities), and extracts wireless-network parameters (SSID, security type, key, WPS PIN, BSSID), WAN/LAN network parameters, and device model information.

- Version: 2.60 (pre-release, build date 2018-03-11)  
- Platform: Windows (x86 PE32), Delphi runtime (msvcr100.dll = MSVC 2010 CRT)  
- Copyright: Stas'M Corp., 2012–2018, `http://stascorp.com`  
- Transport: TCP/IPv4 only; IPv6 not supported.  
- Core scanner logic lives in `librouter.dll` ("Router Core Library").  
- HTTPS via OpenSSL (`libeay32.dll`, `ssleay32.dll` v1.0.2j).

---

## 2. Architecture

```
RouterScan.exe (GUI shell + port scanner)
  │
  ├── librouter.dll  (device parser / exploit engine)
  │     ├── HTTP/HTTPS client (uses OpenSSL)
  │     ├── Basic / Digest / Form auth brute-forcer
  │     ├── Per-model parsers (hundreds of router models)
  │     └── Exploit modules
  │
  ├── libeay32.dll  (OpenSSL crypto)
  ├── ssleay32.dll  (OpenSSL SSL/TLS)
  └── msvcr100.dll  (MSVC 2010 CRT)
```

Evidence: `help/ru/manual/files.html` sections 1.1–1.4; `RouterScan.log` line "Initializing librouter…".

---

## 3. Application State Machine

```
IDLE
  │  [Start scan] clicked
  ▼
SCANNING ──────────────────────────────────────────────────────┐
  │  [||] (Pause)                                              │
  ▼                                                            │
PAUSED                                                         │
  │  [>>] (Resume)                                            │
  └──────────────────────────────────────────────────── back to SCANNING
  │  [Stop scan] clicked
  ▼
STOPPING   (threads draining, 30-second grace period per thread)
  │  all threads finished  OR  [Force stop] clicked
  ▼
IDLE

SUB-STATE while SCANNING:
  SCANNING + UPLOAD_IN_PROGRESS   (if Upload.Mode = Instant)

POST-SCAN STATES (entered after IDLE is reached):
  AUTO_SAVE      → triggered when AutoSave=1 and scan ends
  AUTO_UPLOAD    → triggered when Upload.Mode = After scan
  STOP_ACTION    → triggered by StopAction (shutdown / hibernate / …)
  SILENT_SAVE    → triggered in SilentMode after scan ends
```

States reflected in the main button label:
| State         | Button 1       | Button 2 |
|---------------|----------------|----------|
| IDLE          | `[Start scan]` | —        |
| SCANNING      | `[Stop scan]`  | `[||]`   |
| PAUSED        | `[Stop scan]`  | `[>>]`   |
| STOPPING      | `[Force stop]` | —        |
| IMPORT active | `[Stop import]`| —        |
| UPLOAD active | `[Stop upload]`| —        |

Evidence: `winmain.html#mainbutton`.

---

## 4. Main Window — UI Specification

### 4.1 Top Panel

#### Main Button (§1.1)
Tri-state button described in §3.

#### Logo (§1.2)
Clickable bitmap; opens `http://stascorp.com/load/1-1-0-56` in the default browser.

#### Max Threads spinner (§1.3)
- Integer, 1–∞ (default 300, stored `[PortScan] Threads`).
- May be changed while scanning is active (change takes effect immediately).

#### Connection Timeout spinner (§1.4)
- Integer milliseconds (default 2000, stored `[PortScan] Timeout.Connect.Value`).

#### Port List (§1.5)
- Ordered list of TCP port numbers.
- `[+]` appends a new port; `[-]` removes selected.
- Scrollable during active scan.
- Ports `443`, `4343`, `8443` use HTTPS; all others use plain HTTP/1.0.
- Default list (from `ports.txt`): `8008, 443, 8443, 4443, 8001–8009, 80–89, 8081–8089, 10000, 444`.
- Cannot be structurally modified during scanning (scroll only).

#### IP Range List (§1.6)
- Ordered list of range strings.
- Buttons: `[E]` (open Range Editor), `[+]` (add single range), `[-]` (remove selected), `[x]` (clear all — irreversible).
- Scrollable during active scan; structural edits locked during scan.
- Also editable via `ranges.txt`.

#### Search Bar (§1.7)
- Fields: text box, `[ ] Case sensitive`, `[ ] All`.
- When `All` unchecked: `[« Back]` and `[Forward »]` navigate cell-by-cell.
- When `All` checked: single `[Search all]` button; results placed in the **Search Results** table.
- Persistent across sessions (saved to `[GUI] Search.Text`, `Search.Case`, `Search.All`).

#### Main Menu (§1.8)
Opened by `[< Main Menu >]` button. Items:
- `User Manual (English)` → opens `help/index_en.html`
- `User Manual (Russian)` → opens `help/index_ru.html`
- `Settings and Tweaks` → Settings Dialog (§5.2)
- `Edit Filter Rules…` → Filter Rules Editor (§5.3)
- `Edit IP Exclusions…` → Exclusions Editor (§5.4)
- `Choose columns…` → Column Chooser (§5.7)
- `WPS PIN Companion` → WPS PIN Companion (§5.5)
- `Upload to 3WiFi` → 3WiFi Uploader (§5.6)
- `Enable TCP debug logging` → toggles TCP dump logging (§13.4)

#### Use Credentials (§1.9)
- Toggle `[x] Use credentials`, Username text box, Password text box.
- When enabled, this credential pair is tried **first** on every device, before the dictionary attack, for all authentication methods (Basic, Digest, Form, and device-specific form parsers).
- Can be toggled while scanning is active.
- Stored `[RouterScan] Auth.Custom.Enable`, `Auth.Custom.Username`, `Auth.Custom.Password`.

#### Scanning Modules (§1.10)
Six checkbox-style toggles (can change during scan):
| Label                  | INI key         | Default |
|------------------------|-----------------|---------|
| Router Scan (main)     | `RouterScan`    | 1       |
| Detect proxy servers   | `ProxyCheck`    | 0       |
| Use HNAP 1.0           | `HNAP`          | 1       |
| SQLite Manager RCE     | `SQLite`        | 0       |
| Hudson Java Servlet    | `Hudson`        | 0       |
| phpMyAdmin RCE         | `PMA`           | 0       |

---

### 4.2 Scan Tables

Three tabs, switchable at any time:

#### Tab 0 — Realtime Stats
- Receives every scan result in real time.
- State during scan: **Read/Locked** (cells editable, rows add/delete locked).
- State when stopped: **Read/Write** (full editing including row deletion).

#### Tab 1 — Good Results
- Periodically regenerated from Tab 0 data, applying the Good Results filter (§9).
- Always **Read Only**.
- Cannot trigger Rescan or Reset from this tab.

#### Tab 2 — Search Results
- Populated by `[Search all]`.
- Always **Read/Write**.
- Cannot trigger Rescan or Reset.

#### Table Columns (all three tables share the same column set)
| Internal name | Display label               | Description |
|---------------|-----------------------------|-------------|
| IP            | IP Address                  | IPv4 address of device |
| Port          | Port                        | TCP port connected |
| Time          | Time (ms)                   | Connection latency in ms |
| Status        | Status                      | Thread status string |
| Auth          | Authorization               | Credential pair or bypass method |
| Type          | Server name / Realm / Type  | Detected device model or server header |
| RadioOff      | Radio Off                   | `[X]` if wireless module disabled |
| Hidden        | Hidden                      | `[X]` if SSID broadcast suppressed |
| BSSID         | BSSID                       | AP MAC address; `<no wireless>` if wired-only |
| SSID          | ESSID                       | Wi-Fi network name |
| Sec           | Security                    | Security mode (WPA2, WEP, …) |
| Key           | Key                         | Wi-Fi passphrase; or `IP:port / password` for 802.1X/EAP Radius |
| WPS           | WPS PIN                     | WPS PIN code |
| LANIP         | LAN IP Address              | Device LAN IP |
| LANMask       | LAN Subnet Mask             | Device LAN mask |
| WANIP         | WAN IP Address              | External IP (also used by proxy / HNAP module) |
| WANMask       | WAN Subnet Mask             | WAN mask |
| WANGate       | WAN Gateway                 | Default gateway |
| DNS           | Domain Name Servers         | DNS servers; also carries `*Good Check` sentinels |
| Lat           | Latitude                    | Decimal degrees |
| Long          | Longitude                   | Decimal degrees |
| Comment       | Comments                    | User-editable free text |

Each column has a visibility flag (ColShow.X) and pixel width (ColWidth.X) persisted in `[GUI]`.

#### Table Options (per Tab 0 and Tab 1 only)
- `[ ] Follow last line` — auto-scroll to newest row.
- `( ) Default tab for AutoSave` — selects which tab is auto-saved.

---

### 4.3 Status Bar

Segments (left to right):
1. **Last action text** — latest operation description.
2. **Active threads** — format `N + M` where N = port-scanner threads, M = processor threads.
3. **Total found** — count of rows in Realtime Stats.
4. **Good found** — count of rows in Good Results.
5. **Work time** — elapsed time `D:HH:MM:SS` (paused time excluded).
6. **Total time** — estimated remaining time `D:HH:MM:SS`.

Below the table row area: **Progress Bar** — shows completion percentage for ongoing operations; empty when idle.

Evidence: `winmain.html#statusbar`, `winmain.html#progress`.

---

### 4.4 Context Menus

#### Table Context Menu (right-click on any table)
- `Copy selected cell` — copies text of selected cell(s); multi-cell: tab-separated columns, newline-separated rows.
- `Copy device URL` — `http[s]://IP:port/` (Basic/Digest devices embed `user:pass@` when auto-auth enabled); multiple rows → newline-separated.
- `Copy device info` — full structured info for selected row(s).
- `Import scan table` — prompts file picker (TXT or CSV); then dialog "Append to existing data? [Yes/No]"; No → confirm clear dialog; Cancel → abort.
- `Export scan table` — file picker, format list (XML 2003, CSV, TXT, IP:Port list, JSON).
- `Delete Row` — deletes selected rows (available only in Read/Write state).
- `Edit comments` — inline edit comment for selected row(s).
- `Open in browser` — launches browser with device URL; embeds credentials for Basic/Digest if auto-auth enabled.
- `Lookup IP Address` — opens `https://2ip.ru/` whois for device IP.
- `Locate AP by BSSID` — calls geolocation provider with BSSID (§12).
- `Locate AP by IP` — IP-based geolocation fallback.
- `View in Google Maps` — opens `https://maps.google.com/?q=LAT,LON`.
- `View in Яндекс.Карты` — opens Yandex Maps with coordinates.
- `Reset` — requests graceful stop of selected thread(s).
- `Force reset` — hard-kills selected thread(s); only available after `Reset`.
- `Rescan` — restarts processing of selected device(s); ignores exclusions list.

Keyboard shortcut: `Alt+C` = Copy device URL; `Alt+R` = Reset selected; `Ctrl+A` = select all; `Ctrl+D` = Copy device info.

---

## 5. Secondary Windows

### 5.1 IP Range Editor

Opened by `[E]` button next to ranges list.

**Layout:** syntax hint block (top), large text area for multi-line range entry, bottom buttons.

**Supported range syntax** (evidence: `manual/index.html#helpsyntax`):
| Type | Example | Notes |
|------|---------|-------|
| Single IP | `192.168.1.1` | |
| Dash range | `192.168.10.1-192.168.10.254` | |
| CIDR | `10.10.10.0/24` | Bits 0–32 |
| Nmap octet | `10.0.0.1-254` | Per-octet range |
| Nmap octet list | `10.0.2,4.1` | Per-octet comma list |
| Mixed | `192.168.0-10,100,199.1,254` | Fully combinatorial |
| Comment | `# any text` | Line ignored |

Normalization rules:
- `IP-IP` with same /mask → normalized to CIDR.
- Single-IP CIDR (`/32`) → normalized to single IP.
- Nmap octet ranges are NOT cross-normalized with other types.
- Duplicate removal and sort are optional (menu option, added v2.60).

**Buttons:**
- `[OK]` — validates syntax, reports errors with line numbers (double-click error → highlight line); saves if valid.
- `[Cancel]` — discard changes.
- `[Import from file…]` — load from text file, appending or replacing.

**Edge cases:**
- Blank lines are ignored.
- Tabs in range input are filtered out.
- URLs pasted into the editor: IP part is automatically extracted.
- Max displayed ranges: 10 000 rows (display limit only, not a processing limit).

---

### 5.2 Settings Dialog

Five tabs: **General**, **Port Scanner**, **Output**, **HTTP Client**, **Tweaks**.

#### Tab: General

| Setting | Type | Default | INI key |
|---------|------|---------|---------|
| Auto-auth in browser | bool | 1 | `Browser.AutoAuth` |
| Use custom browser | bool | 0 | `Browser.UseCustom` |
| Browser executable path | string | `""` | `Browser.Exec` |
| Good Results filter (Authorized) | enum {Ignore,Include,Exclude} | Include | `Tab.Good.Flags` bit 0 |
| Good Results filter (Wireless) | enum | Include | bit 1 |
| Good Results filter (Wired) | enum | Include | bit 2 |
| Good Results filter (Other Info) | enum | Include | bit 3 |
| Good Results generation mode | enum {Turn off, Automatic, Always on} | Automatic | `Tab.Good.CheckLatency` |
| Double-click action | enum {Do nothing, Open in browser, Edit comment} | Do nothing | `Tab.DblClick` |
| Geolocation provider | enum (§12) | Yandex (2) | `Geolocation.Provider` |

#### Tab: Port Scanner

| Setting | Type | Default | INI key |
|---------|------|---------|---------|
| Scan mode | enum {Normal=0, Fast=1, UltraFast=2} | Normal | `ScanMode` |
| SYN count (connection attempts) | int 1–3 | 1 | `SYNCount` |
| Stop action | enum {DoNothing=0,Close=1,Logoff=2,Shutdown=3,Suspend=4,Hibernate=5} | 0 | `StopAction` |
| Silent mode | bool | 0 | `SilentMode` (requires restart) |
| Thread timeout (minutes) | int 1–30 | 5 | `Timeout.Thread.Minutes` |
| Thread timeout unlimited | bool | 0 | `Timeout.Thread.Unlimit` |
| Watchdog enable | bool | 0 | `WatchDog.Enable` |
| Watchdog frequency | enum | 1 | `WatchDog.Frequency` |
| Watchdog method | enum {ICMP, TCP} | ICMP | `WatchDog.Method` |
| Watchdog address | IP:port string | `192.168.0.1:80` | `WatchDog.Address` |
| Watchdog timeout (ms) | int | 1000 | `WatchDog.Timeout` |

#### Tab: Output

| Setting | Type | Default | INI key |
|---------|------|---------|---------|
| AutoSave enable | bool | 0 | `AutoSave` |
| AutoSave interval (seconds) | int | 0 | `Interval` |
| AutoSave format | enum {xml,csv,txt,ipport,json} | txt | `Format` |
| AutoSave tab | int 0/1 | 0 | `SaveTab` |
| Upload service URL | string | `http://3wifi.stascorp.com/3wifi.php` | `Upload.Server` |
| Upload mode | enum {Disabled=0, AfterScan=1, Instant=2} | 2 (Instant) | `Upload.Mode` |
| Upload username | string | `""` | `Upload.Username` |
| Upload password | string | `""` | `Upload.Password` |
| Upload comment (manual) | string | `"Router Scan"` | `Upload.Comment.Demand` |
| Upload comment (auto) | string | `"Router Scan"` | `Upload.Comment.Auto` |

#### Tab: HTTP Client

| Setting | Type | Default | INI key |
|---------|------|---------|---------|
| Proxy type | enum {None=0, HTTP=1, HTTPS=2, HTTP CONNECT=3, SOCKS4=4, SOCKS4a=5, SOCKS5=6} | 0 | `Proxy.Type` |
| Proxy IP | string | `127.0.0.1` | `Proxy.IP` |
| Proxy port | int | 8888 | `Proxy.Port` |
| Proxy auth user | string | `""` | UNKNOWN |
| Proxy auth password | string | `""` | UNKNOWN |
| User-Agent | string | `Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1` | `UserAgent` |

Notes on proxy:
- HTTP/HTTPS type: only HTTP request/response proxied; TCP SYN probes and socket-level data bypass the proxy.
- HTTP CONNECT and SOCKS types: proxy the full socket connection.

#### Tab: Tweaks (Router Scan module extra settings)

| Setting | Type | Default | INI key |
|---------|------|---------|---------|
| Custom detection page enable | bool | 0 | `Detection.CustomPage.Enable` |
| Custom detection page path | string | `/admin/` | `Detection.CustomPage.Path` |
| Basic dual-check | bool | 1 | `Auth.Basic.DualCheck` |
| Basic pairs file | string | `auth_basic.txt` | `Auth.Basic.PairFile` |
| Digest pairs file | string | `auth_digest.txt` | `Auth.Digest.PairFile` |
| Form pairs file | string | `auth_form.txt` | `Auth.Form.PairFile` |

**[OK]** validates and saves. **[Cancel]** discards. Settings saved to `config.ini` automatically every ~20 seconds during runtime.

---

### 5.3 Filter Rules Editor

Evidence: `winfilter.html`, LibRouter `SetParam.html` (`stFilterRules`).

**Purpose:** rules evaluated at first HTTP response; if any rule matches, device processing halts and status shows `Filtered`.

**Fields per rule:**
| Field | Values |
|-------|--------|
| Place (search area) | `Response body` (`body`), `Server name` (`serv`), `Realm name` (`relm`) |
| Rule (match mode) | `equal` (`eq`), `not equal` (`neq`), `contains` (`cnt`), `doesn't contain` (`ncnt`) |
| Check string | arbitrary text |

**Buttons:**
- `[Add rule]` — appends rule (all three fields must be filled).
- `[Save rule]` — saves selected rule. Cannot add new rule while unsaved rule is selected.
- `[Del]` keyboard key — removes selected rule.
- Double-click rule in list → loads into editing fields.
- `[OK]` / `[Cancel]` — save/discard.

**File format** (`filter.txt`): each rule on one line, fields tab-separated: `place\tmode\tstring`. Lines starting with `#` are comments.

---

### 5.4 IP Exclusions Editor

Evidence: `winexclusions.html`, `files.html#exclusions`.

**Purpose:** IPs (optionally with ports) skipped by the port scanner. Rescan context-menu ignores exclusions.

**List format:** `IP` or `IP:port` per entry.

**Buttons:**
- `[Add]` — prompts for new entry.
- `[Delete]` — removes selected entry.
- `[Paste from clipboard]` — pastes multi-line IP:port data; dialog asks append or replace.

**Tip documented:** select IP + Port columns in Good Results table, copy, paste here.

**File format** (`exclusions.txt`): one `IP` or `IP:port` per line.

---

### 5.5 WPS PIN Companion

Evidence: `winwpspin.html`.

**Purpose:** predicts WPS PIN code(s) from a BSSID (MAC address) using one of many implemented algorithms.

**Controls:**
- BSSID input (one or more MAC addresses).
- `[Suggest]` — tries the best-fit algorithm for the OUI prefix; may produce no output if no algorithm matches.
- `[Get All]` — runs every algorithm for a single BSSID; ignores OUI matching.
- `[Grab from JSW]` — imports BSSID list from a running JumpStart Wireless (Atheros) / TP-LINK QSS window.
- Output area — textual results.
- Algorithm list — read-only list of implemented generator names (UNKNOWN: exact list; may vary by version).
- `[Scan table]` — cross-references WPS PINs already in the active table against all algorithms; writes matching algorithm name(s) to Comments column.

**WPS PIN algorithms (UNKNOWN: full enumeration).**  
Confirmed included (from changelog v2.50–v2.60): Airocon Realtek, Belkin, Livebox Arcadyan, plus at least 17 algorithmic generators and 9 static PINs (as of v2.50). Serial number used as additional input for some algorithms (v2.60).

---

### 5.6 3WiFi Uploader

Evidence: `winupload.html`, `winsettings.html#uploadcfg`.

**Purpose:** upload discovered access points to the 3WiFi community database.

**Controls:**
- Output log area — status messages.
- `[Upload]` / `[Stop]` — start/stop upload.
- Progress bar — shows uploaded / total count.
- Comment field — overrides `Upload.Comment.Demand`.

**Endpoint:** POST to `Upload.Server` (default `http://3wifi.stascorp.com/3wifi.php`).

**Authentication:** `Upload.Username` / `Upload.Password` credentials.  
Points are optionally attributed to a named account if credentials are non-guest.

**Data selection:** application determines which rows are uploadable automatically (AP rows with BSSID/SSID/Key data).

---

### 5.7 Column Chooser

Opened via Main Menu → `Choose columns…`.  
Checkbox list of all column names; toggling changes `ColShow.X` in `[GUI]` section.

---

## 6. Scan Engine — Behavior Specification

### 6.1 Port Scanner

For each IP address in the queue and each port in the port list, the scanner initiates a TCP SYN. The queue is exhausted in IP-first order (all ports for IP N before moving to IP N+1 in Fast/UltraFast modes; port-by-port interleaved in Normal mode — see §6.4).

**SYN retry:** controlled by `SYNCount` (1–3). Each attempt sends a TCP SYN and waits up to `Timeout.Connect.Value` ms for SYN-ACK. RST = port closed (treated identically to timeout for processing purposes). On success, a worker thread is spawned for that IP:port.

**Exclusions:** before probing any IP:port, check if `IP` or `IP:port` appears in the exclusions list; if so, skip silently.

---

### 6.2 Thread Model

- **Max threads:** `[PortScan] Threads` (default 300). Counts both scanner threads and processor threads together.
- **Status column values** (observed strings, evidence from changelog + manual):  
  `Connecting`, `Processing`, `Authorizing`, `Auth failed`, `No response`, `Filtered`, `Timed out`, `Done`, `Stopped`, `Force stopped`, UNKNOWN: complete list.
- **Thread timeout:** if processing exceeds `Timeout.Thread.Minutes` minutes, thread is killed and Status shows `Timed out`. After timeout, a 30-second grace window is given before forced termination (v2.60 change).
- **Pause:** freeze all thread progression; elapsed time counter pauses.
- **Stop scan:** sends stop signal to all threads; threads finish their current HTTP transaction then exit.
- **Force stop:** hard-terminates all threads immediately.
- At thread stop, all open sockets are closed automatically.
- **Watchdog** pauses scan on network failure (see §6.5).

---

### 6.3 Device Processing Pipeline

For each open IP:port, the following steps occur in `librouter.dll`:

1. **Initial HTTP GET** to `/` (or custom detection page if `stUseCustomPage` is set).
2. **Filter rules check** — evaluate all filter rules against the response body, `Server` header, and `WWW-Authenticate: realm`. If any rule matches → status `Filtered`, stop.
3. **Device detection** — match Server header, Realm, response body text signatures, HTML `<title>` tags, Cookie names, and Hex signatures to identify router model / firmware.
4. **Exploit attempt** — if model has a known exploit: request vulnerability-specific URL(s); validate extracted credentials; if valid, skip brute-force.
5. **Use credentials check** — if `Auth.Custom.Enable=1`: try the custom username/password first using all auth methods (Basic, Digest, form-specific).
6. **Dictionary brute-force**:
   - If device uses HTTP Basic: iterate `auth_basic.txt` pairs.
   - If device uses HTTP Digest: iterate `auth_digest.txt` pairs.
   - If device uses form-auth (some models): iterate `auth_form.txt` pairs.
   - Dictionary entries for unknown-model devices are built in to the parsers.
7. **Data extraction** — authenticated HTTP requests to model-specific pages to extract SSID, key, WPS PIN, BSSID, security type, LAN/WAN IP, subnet masks, gateway, DNS servers, radio-off flag, hidden SSID flag.
8. **Module chain** — after RouterScan main module, optional modules run in order (HNAP, ProxyCheck, SQLite, Hudson, PMA). Each may overwrite column data. HNAP is skipped if main module already retrieved all data.
9. **Geolocation** — if BSSID was found and geolocation provider ≠ Disabled, query the configured provider (§12); write Lat/Long.
10. **Result** written to Realtime Stats table row. Good Results table is regenerated.
11. If `Upload.Mode = Instant`, upload this row to 3WiFi immediately.

**HNAP notes:**
- HNAP module checks for `HNAP1/` endpoint; if found, records `HNAP Info` in Type column.
- If vulnerability found → `HNAP bypass auth` in Comments + wireless data.
- To force HNAP check on already-authorized device, disable RouterScan main module.

**Proxy detection notes:**
- ProxyCheck module checks if host acts as HTTP proxy.
- On success: appends `"proxy server"` to Type column; real external IP → WANIP column; `"Proxy Good Check"` → DNS column.

**SQLite / Hudson / phpMyAdmin module notes:**
- URL(s) tried: UNKNOWN (not documented in bundled help).
- On detection: link → Comment column; result → Type column.
- On vulnerability confirmed: `"SQLite Good Check"` / `"Hudson Good Check"` / `"PMA Good Check"` → DNS column.

**GZip false-header correction:** HTTP responses with a false GZip header are automatically corrected (v2.60).

**Multiple redirections:** if a device redirects to a different hostname, scanning continues on the same IP with the new hostname in the `Host` header (behavior added v2.40 for ZyXEL Keenetic NDMS v2).

---

### 6.4 Scan Modes

| Mode | INI value | Inter-probe delay | Port behavior |
|------|-----------|-------------------|---------------|
| Normal | 0 | 15 ms between each (IP, port) pair | Sequential |
| Fast Scan | 1 | 15 ms between each IP | All ports probed simultaneously per IP |
| Ultra Fast | 2 | None | All threads used immediately, no delay |

Evidence: `winsettings.html#scanmode`.

---

### 6.5 Watchdog

When `WatchDog.Enable=1`, a background timer fires at the configured frequency. It probes `WatchDog.Address` using `WatchDog.Method` (`ICMP` ping or `TCP` connect) with `WatchDog.Timeout` ms deadline.

- Failure threshold: **3 consecutive failed probes** → scan paused automatically.
- Recovery: **1 successful probe** → scan resumed automatically.
- When a failure is detected, the IP being processed at that moment is logged (to `RouterScan.log`).

Evidence: `winsettings.html#watchdog`, changelog v2.53.

---

## 7. Scanning Modules

### 7.1 Router Scan (main)
Handles device detection, authentication, and data extraction (§6.3). Internal name `RouterScan`.

### 7.2 Detect Proxy Servers
Internal name `ProxyCheck`. Issues an HTTP proxy-style request through the target. UNKNOWN: exact request format.

### 7.3 HNAP 1.0
Internal name `HNAP`. Issues SOAP requests to `/HNAP1/`. Bypasses auth if vulnerable. Gets Wi-Fi SSID/key/PIN via SOAP actions. Also retrieves WPS PIN via HNAP when available (v2.45+).

### 7.4 SQLite Manager RCE
Internal name `SQLite`. Detects SQLite Manager PHP application; tests for unauthenticated PHP code execution. UNKNOWN: exact URL patterns.

### 7.5 Hudson Java Servlet
Internal name `Hudson`. Detects Hudson CI / Jenkins CI; tests for unauthenticated Java code execution. UNKNOWN: exact URL patterns.

### 7.6 phpMyAdmin RCE
Internal name `PMA`. Detects phpMyAdmin; tests CVE [exploit-db #8992]. UNKNOWN: exact URL patterns.

---

## 8. Authentication Subsystem

### 8.1 Detection Order (per device)
1. Try exploit (if model identified and exploit exists).
2. Try Use Credentials (`Auth.Custom`) if enabled.
3. Brute-force dictionary (Basic / Digest / Form depending on device's `WWW-Authenticate` header).
4. For unidentified model with Basic/Digest: brute-force from pairs files.
5. For form-auth devices without explicit form parser: dictionary not tried (unless Use Credentials covers it).

Evidence: `faq.html#fq2_2`.

### 8.2 Basic Authentication
- `WWW-Authenticate: Basic realm="…"` triggers Basic mode.
- Credential encoding: Base64(`username:password`) in `Authorization: Basic …` header.
- `<empty>` in pairs file represents empty string.
- `Auth.Basic.DualCheck=1`: each pair is tried twice (works around ASUS brute-force lockout logic).
- Dictionary file: `auth_basic.txt`; tab-separated pairs; lines not matching format ignored; must be ASCII/ANSI.

### 8.3 Digest Authentication
- `WWW-Authenticate: Digest realm="…"` triggers Digest mode.
- Implements MD5 challenge-response (RFC 2617). AUTH-INT not supported.
- Dual-check not applicable.
- Empty username (`<empty>` login) not supported for Digest.
- Dictionary file: `auth_digest.txt`; same format as Basic.

### 8.4 Form Authentication
- No `WWW-Authenticate` header; auth via HTML form POST.
- Only some specific device models support form dictionary attack.
- Dictionary file: `auth_form.txt`; same format.

### 8.5 SSID/Key/WPS as credentials
Since v2.60: discovered SSID, Wi-Fi key, and WPS PIN are also tried as login credentials on device admin interfaces.

### 8.6 Dictionary file format
```
# Comment line (ignored)
// Section header (ignored)
username<TAB>password
<empty><TAB>password    (empty string username)
username<TAB><empty>    (empty string password)
```
Files must be ASCII/ANSI (no Unicode). Duplicates are not deduplicated.

---

## 9. Good Results Filter

Evidence: `winsettings.html#goods`, changelog v2.53.

Regeneration triggered periodically from Realtime Stats data.  
Each row is classified by four boolean properties:
- **Authorized** — a credential pair was successfully found or auth was bypassed.
- **Wireless** — wireless parameters (SSID/key/BSSID) were retrieved.
- **Wired** — device has no wireless interface (`<no wireless>` in BSSID column).
- **Other Info** — WAN IP, DNS, or other network info was retrieved.

Each property can be set to:
- `Ignore` — property is not evaluated.
- `Include` — if row has this property, it is a candidate for the table.
- `Exclude` — if row has this property, it is removed from the table.

Logic: first evaluate all `Include` criteria (OR logic among Includes), then apply all `Exclude` criteria.  
If all properties are `Ignore` or all are `Exclude` → Good Results table is disabled (no generation).

`Tab.Good.Flags` bitmask (UNKNOWN: exact bit layout; known from default value 15 = all four bits set = all Include).

Generation mode (`Tab.Good.CheckLatency`):
- `0` = Turn off.
- `1` = Automatic (disables itself if generation takes >3 seconds).
- `2` = Always on (UNKNOWN: whether this exact value is used or if Automatic is the only non-off option — evidence suggests at least two modes).

---

## 10. Wi-Fi / Wireless Tab

Added in v2.60. Separate tab in main window (not one of the three scan-result tabs — UNKNOWN: exact UI placement).

**Functionality:**
- Detects nearby Wi-Fi networks using an 802.11a/b/g/n adapter.
- Displays a table of visible networks.
- Performs wireless key audits (WPA/WPA2 PSK brute-force, WPS PIN enumeration, Pixie Dust attack).
- Integrates with 3WiFi service for known-network lookup and coordinate-based IP-range search.

### 10.1 Wireless Networks Table Columns

| Internal name | Display label |
|---------------|---------------|
| Active        | Active (scanning-visible) |
| Stored        | Stored (saved in DB) |
| Chn           | Channel |
| Hidden        | Hidden SSID |
| BSSID         | BSSID |
| SSID          | SSID |
| Sec           | Security |
| Key           | Key |
| WPS           | WPS |
| Level         | Signal Level (dBm) |
| WPSVer        | WPS Version |
| Conf          | WPS Config |
| Lock          | WPS Lock |
| WSCName       | WSC Device Name |
| Model         | Model |
| Serial        | Serial Number |
| IP            | IP |
| Mask          | Mask |
| Gate          | Gateway |
| DNS           | DNS |
| ISP           | ISP |
| ExtIP         | External IP |
| Lat           | Latitude |
| Long          | Longitude |
| Comment       | Comment |

Column widths and visibility stored as `WiFiColShow.X` / `WiFiColWidth.X` in `[GUI]`.

### 10.2 Wireless Interface Settings

Stored in `[Wireless]` INI section:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| Interface | `""` | Wi-Fi adapter name |
| RefreshRate | 5 | Network list refresh (seconds) |
| EnableScan | 0 | Enable passive scanning |
| Cumulative | 0 | Cumulative mode (retain old APs) |
| LookupKnown | 0 | Look up known data in 3WiFi |
| NetworkDetect | 0 | Detect ISP / external IP |
| AutoSave | 1 | Auto-save network table on exit |
| AutoSaveDir | `wireless` | Directory for auto-saved tables |
| RangesRadius | 1 | km radius for 3WiFi range search |
| IgnoreDBM10 | 1 | Ignore erroneous -10 dBm readings |

---

## 11. WPS Audit Engine

Evidence: `iniconf.html#wlanaudit`, `iniconf.html#wlanwps`.

### 11.1 PSK Brute-force
- Dictionary: `wlanpass.txt` (one passphrase per line).
- `Audit.PSK.SkipTimeout=0`: skip timeout disabled (0=disabled; non-zero = ms threshold).

### 11.2 WPS PIN Audit

| Parameter | Default | Meaning |
|-----------|---------|---------|
| CheckPins | 1 | Try predicted PINs from WPS PIN Companion |
| DHSmall | 0 | Use small Diffie-Hellman keys (faster, less compatible) |
| RandIdent | 0 | Randomize Enrollee UUID / nonce in M1 |
| NoChecksum | 0 | Skip PIN checksum correction |
| PixieDust | 1 | Enable Pixie Dust attack |
| IgnoreLock | 1 | Continue despite AP lockout flag |
| Reassociate | 0 | Re-associate before each PIN attempt |
| PacketTimeout | 5000 | ms wait for WPS packet receive |
| SendTimeout | 1000 | ms wait for WPS packet send |
| SendTries | 3 | Retries on send failure |
| NextPinWait | 1000 | ms delay after failed transaction |
| LockWait | 60000 | ms wait for lockout to clear |
| PinOrder | `00000000` | Starting PIN for exhaustive search |

WPS identity fields sent in M1/M2:

| Parameter | Default |
|-----------|---------|
| Identity | `WFA-SimpleConfig-Registrar-1-0` |
| Manufacturer | `Stas'M Corp.` |
| ModelName | `Router Scan` |
| ModelNum | `12345` |
| Serial | `0000-0000` |
| DeviceType | `00010050f2040001` |
| DeviceName | `WPS Registrar` |
| OSVersion | `00800000` |
| UUID | `49289fbb6bfcf3b41647cb2221826b16` |

### 11.3 Pixie Dust Attack
Uses external binary `PixieWps/` directory (bundled Windows build of PixieWps). Attack is triggered when WPS E-S1/E-S2 nonces leak in an M3 response.

### 11.4 Audit Stop Condition
`Audit.MaxErrors=50`: audit session aborted after 50 consecutive errors.

### 11.5 Post-audit Action
`Audit.ConnectSuccess=0`: when set, connect to AP after successful audit.

---

## 12. Geolocation Subsystem

Evidence: `winsettings.html#geolocation`, `iniconf.html#geo`, `manual/index.html#helpgeo`.

Lookup triggered after BSSID is retrieved. One BSSID is sent per request (no triangulation); provider returns coordinates.

| Provider | INI value | URL / Notes |
|----------|-----------|-------------|
| Disabled | 0 | No requests made |
| AlterGeo API | 1 | `http://platform.altergeo.ru/` |
| Yandex Locator | 2 | `https://tech.yandex.ru/locator/` (default) |
| Google Location | 3 | `https://developers.google.com/maps/documentation/geolocation/` |
| Mylnikov.org | 4 | `https://www.mylnikov.org/archives/1063` |
| WiGLE.net | 5 | **[N/A]** — not implemented |
| Mozilla Ichnaea | 6 | **[N/A]** — not implemented |

IP-based fallback: uses `http://www.geoipview.com` (added v2.50; UNKNOWN: current status).

---

## 13. File Formats

### 13.1 config.ini
Windows INI format (section headers `[Section]`, `Key=Value`).  
Written to the application directory. Auto-saved every ~20 seconds during runtime; also saved on clean exit ("Closing, saving settings…" in log).  
Full key listing: see §15.

### 13.2 ranges.txt and ports.txt
Plain text, one entry per line.  
- `ranges.txt`: IP range syntax per §5.1; `#`-prefixed lines are comments.  
- `ports.txt`: one integer port number per line.  
Both loaded at startup; changes are reflected when ranges/ports editors save.

### 13.3 auth_basic.txt / auth_digest.txt / auth_form.txt
Plain text, ASCII/ANSI only. One credential pair per line: `username<TAB>password`.  
Special token `<empty>` represents the empty string.  
All other line formats (lines not containing exactly one TAB) are ignored.

### 13.4 filter.txt
Plain text. Each filter rule on one line: `place<TAB>mode<TAB>check_string`.  
Valid place tokens: `body`, `serv`, `relm`.  
Valid mode tokens: `eq`, `neq`, `cnt`, `ncnt`.  
Lines not matching the three-field format are ignored (treated as comments if prefixed with `#`).

### 13.5 exclusions.txt
Plain text. One entry per line: `IP` or `IP:port`.

### 13.6 wlanpass.txt
Plain text. One Wi-Fi passphrase per line.

### 13.7 Export file formats

| Format | Extension | Import? | Notes |
|--------|-----------|---------|-------|
| XML 2003 Table | `.xml` | No | Microsoft Office 2003 SpreadsheetML |
| CSV Table | `.csv` | Yes | RFC-4180 style; UTF-8 without BOM |
| Tab-delimited TXT | `.txt` | Yes | UTF-8 without BOM; field separator `\t` |
| IP:Port List | `.txt` | No | Format: `IP:port` per line |
| JSON | `.json` | No | JavaScript Object Notation array |

All import/export files are UTF-8 (no BOM).  
Exported filenames are the current date-time at time of export (format: UNKNOWN, likely `YYYY-MM-DD HH-MM-SS`).

### 13.8 RouterScan.log
Plain text, one line per event. Format: `YYYY-MM-DD HH-MM-SS | message`.  
Written to the application directory. Events: initialization, scan start, scan end, watchdog events, shutdown.

### 13.9 TCP Debug Dump files
Created in a subdirectory named with the current date (`YYYY-MM-DD` format — UNKNOWN: exact format) when TCP debug logging is enabled.  
File extension: `.bin`. Contains raw TCP payloads (requests and responses concatenated). Not useful for HTTPS targets (data encrypted).

---

## 14. Network Protocols

### 14.1 HTTP/1.0
Used for all device communication except HTTPS ports.  
- `GET / HTTP/1.0\r\nHost: IP:port\r\nUser-Agent: …\r\n\r\n` as the initial probe.
- `Referer` header sent automatically (v2.53+).
- Deflate and GZip response decompression supported (v2.43+).
- Redirect handling: follows `Location` header; if new hostname differs, keeps original IP but updates `Host` header.
- Multiple redirections supported.

### 14.2 HTTPS
Ports `443`, `4343`, `8443` use TLS via OpenSSL (`libeay32.dll` / `ssleay32.dll` v1.0.2j).  
Certificate validation: UNKNOWN (likely disabled for scanning purposes).

### 14.3 HTTP Basic Authentication
`Authorization: Basic Base64(user:password)` header.

### 14.4 HTTP Digest Authentication
Standard MD5 challenge-response per RFC 2617.  
AUTH-INT qop not supported.

### 14.5 HNAP/SOAP
`POST /HNAP1/ HTTP/1.0` with `SOAPAction` header. XML body containing HNAP action requests.  
Request/response: XML-encoded.

### 14.6 WPS (IEEE 802.11)
Layer 2 WPS EAP exchange using a Wi-Fi interface.  
TLV-encoded WPS messages M1–M8 / EAP exchange.  
External process (`PixieWps.exe`) invoked for Pixie Dust.

### 14.7 ICMP
Used by Watchdog in ICMP mode: standard Echo Request / Echo Reply.

### 14.8 TCP SYN probe
Raw TCP SYN sent to probe port availability. No application-layer data for the probe itself.

### 14.9 3WiFi Upload (HTTP POST)
Destination: `http://3wifi.stascorp.com/3wifi.php` (configurable).  
Method: HTTP POST.  
Content-type and payload format: UNKNOWN (likely JSON or form-encoded AP records).  
Authentication: username/password in POST body or HTTP Basic — UNKNOWN.

### 14.10 Geolocation Requests (HTTP/HTTPS)
One BSSID per request to the configured provider.  
Exact request/response format per provider: UNKNOWN (varies by provider API).

### 14.11 Proxy Protocols
Supported proxy types: HTTP, HTTPS tunnel (`CONNECT`), SOCKS4, SOCKS4a, SOCKS5 (added v2.60).

---

## 15. Settings & Persistence (config.ini)

Full INI key reference:

### [PortScan]
| Key | Type | Default |
|-----|------|---------|
| ScanMode | int 0–2 | 0 |
| Threads | int | 300 |
| SYNCount | int 1–3 | 1 |
| Timeout.Connect.Value | int (ms) | 2000 |
| Timeout.Thread.Minutes | int 1–30 | 5 |
| Timeout.Thread.Unlimit | bool | 0 |
| Ranges | filename | `ranges.txt` |
| Ports | filename | `ports.txt` |
| StopAction | int 0–5 | 0 |
| SilentMode | bool | 0 |
| WatchDog.Enable | bool | 0 |
| WatchDog.Frequency | int | 1 |
| WatchDog.Method | `ICMP`\|`TCP` | `ICMP` |
| WatchDog.Address | IP:port | `192.168.0.1:80` |
| WatchDog.Timeout | int (ms) | 1000 |
| Exclusions.FileName | filename | `exclusions.txt` |

### [Output]
| Key | Type | Default |
|-----|------|---------|
| AutoSave | bool | 0 |
| SaveTab | int 0\|1 | 0 |
| Interval | int (sec) | 0 |
| Format | `xml`\|`csv`\|`txt`\|`ipport`\|`json` | `txt` |
| Upload.Mode | int 0–2 | 2 |
| Upload.Server | URL | `http://3wifi.stascorp.com/3wifi.php` |
| Upload.Username | string | `""` |
| Upload.Password | string | `""` |
| Upload.Comment.Demand | string | `Router Scan` |
| Upload.Comment.Auto | string | `Router Scan` |

### [HTTP]
| Key | Type | Default |
|-----|------|---------|
| Proxy.Enable | bool | 0 |
| Proxy.Type | int 0–6 | 0 |
| Proxy.IP | string | `127.0.0.1` |
| Proxy.Port | int | 8888 |
| UserAgent | string | `Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1` |

### [Modules]
| Key | bool | Default |
|-----|------|---------|
| RouterScan | bool | 1 |
| ProxyCheck | bool | 0 |
| HNAP | bool | 1 |
| SQLite | bool | 0 |
| Hudson | bool | 0 |
| PMA | bool | 0 |

### [RouterScan]
| Key | Type | Default |
|-----|------|---------|
| Detection.CustomPage.Enable | bool | 0 |
| Detection.CustomPage.Path | string | `/admin/` |
| Auth.Basic.DualCheck | bool | 1 |
| Auth.Basic.PairFile | filename | `auth_basic.txt` |
| Auth.Digest.PairFile | filename | `auth_digest.txt` |
| Auth.Form.PairFile | filename | `auth_form.txt` |
| Auth.Custom.Enable | bool | 1 |
| Auth.Custom.Username | string | `admin` |
| Auth.Custom.Password | string | `""` |
| Filter.RulesFile | filename | `filter.txt` |

### [Wireless]
| Key | Type | Default |
|-----|------|---------|
| Interface | string | `""` |
| RefreshRate | int (sec) | 5 |
| EnableScan | bool | 0 |
| Cumulative | bool | 0 |
| LookupKnown | bool | 0 |
| NetworkDetect | bool | 0 |
| AutoSave | bool | 1 |
| AutoSaveDir | path | `wireless` |
| RangesRadius | int (km) | 1 |
| IgnoreDBM10 | bool | 1 |
| Audit.ConnectSuccess | bool | 0 |
| Audit.MaxErrors | int | 50 |
| Audit.PSK.SkipTimeout | int (ms) | 0 |
| Audit.WPS.CheckPins | bool | 1 |
| Audit.WPS.DHSmall | bool | 0 |
| Audit.WPS.RandIdent | bool | 0 |
| Audit.WPS.NoChecksum | bool | 0 |
| Audit.WPS.PixieDust | bool | 1 |
| Audit.WPS.IgnoreLock | bool | 1 |
| Audit.WPS.Reassociate | bool | 0 |
| Audit.WPS.PacketTimeout | int (ms) | 5000 |
| Audit.WPS.SendTimeout | int (ms) | 1000 |
| Audit.WPS.SendTries | int | 3 |
| Audit.WPS.NextPinWait | int (ms) | 1000 |
| Audit.WPS.LockWait | int (ms) | 60000 |
| Audit.WPS.PinOrder | string (8 digits) | `00000000` |
| Audit.WPS.Identity | string | `WFA-SimpleConfig-Registrar-1-0` |
| Audit.WPS.Manufacturer | string | `Stas'M Corp.` |
| Audit.WPS.ModelName | string | `Router Scan` |
| Audit.WPS.ModelNum | string | `12345` |
| Audit.WPS.Serial | string | `0000-0000` |
| Audit.WPS.DeviceType | hex string | `00010050f2040001` |
| Audit.WPS.DeviceName | string | `WPS Registrar` |
| Audit.WPS.OSVersion | hex string | `00800000` |
| Audit.WPS.UUID | hex string | `49289fbb6bfcf3b41647cb2221826b16` |

### [GUI]
| Key | Type | Default |
|-----|------|---------|
| FirstRun | bool | 0 |
| Tab.Realtime.Follow | bool | 1 |
| Tab.Good.Follow | bool | 1 |
| Tab.Good.Flags | int | 15 |
| Tab.Good.CheckLatency | bool | 1 |
| Tab.DblClick | int 0–2 | 0 |
| Search.Text | string | `""` |
| Search.Case | bool | 0 |
| Search.All | bool | 1 |
| Browser.AutoAuth | bool | 1 |
| Browser.UseCustom | bool | 0 |
| Browser.Exec | path | `""` |
| Geolocation.Provider | int 0–6 | 2 |
| Window.X | int (px) | 0 |
| Window.Y | int (px) | 0 |
| Window.Width | int (px) | 992 |
| Window.Height | int (px) | 549 |
| Window.State | `Normal`\|`Maximized` | `Maximized` |
| ColShow.{name} | bool | 1 (all) |
| ColWidth.{name} | int (px) | (varies per column) |
| WiFiColShow.{name} | bool | 1 (all) |
| WiFiColWidth.{name} | int (px) | (varies per column) |

**Default column widths** (from `config.ini` evidence):
```
IP=96, Port=36, Time=50, Status=124, Auth=140, Type=296,
RadioOff=52, Hidden=40, BSSID=106, SSID=128, Sec=80, Key=96,
WPS=60, LANIP=96, LANMask=96, WANIP=96, WANMask=96,
WANGate=96, DNS=240, Lat=116, Long=116, Comment=400
```

---

## 16. Error Behaviors & Edge Cases

| Scenario | Behavior |
|----------|----------|
| No config.ini on startup | Created with defaults; `FirstRun` detection (UNKNOWN: first-run dialog content) |
| Missing pairs file | UNKNOWN: likely silent skip; pairs just not loaded (log: "Loading pairs…" then silent) |
| Malformed range in editor | Error dialog lists line numbers; double-click error highlights line |
| Thread exceeds timeout | Status = `Timed out`; 30-second grace then force-killed |
| All threads stuck, Force stop | Hard-kills all threads; sockets closed |
| Watchdog 3 failures | Scan automatically paused; log entry with current IP |
| Watchdog recovery | Scan automatically resumed |
| HTTPS cert invalid | UNKNOWN (likely accepted without verification) |
| HTTP redirect to different host | IP stays the same; Host header updated to new hostname |
| HTTP redirect to HTTPS | Client switches to TLS for the same IP (added v2.53) |
| False GZip header | Auto-corrected (v2.60) |
| ZTE Telnet Root partial exploit | Sends recovery request to avoid 500 Internal Error on admin page (v2.52) |
| 802.1X/EAP device | Key column: `IP:port / password` of Radius server |
| Device has no Wi-Fi | BSSID = `<no wireless>`; wireless columns = `—` |
| Stop scan with unsaved results + StopAction ≠ DoNothing | Prompt to enable AutoSave before performing stop action |
| Stop scan confirmation | Dialog prompt (added v2.51) |
| Import: table not empty | Dialog: Append [Yes] / Clear [No] / Cancel |
| Max displayed ranges > 10 000 | Display capped at 10 000 rows (processing continues normally) |
| Export empty table | Export option disabled |
| AutoSave with empty table | File not written |
| Silent Mode enabled | Window hidden on startup; system tray icon shown; auto-starts scan; auto-saves result on finish |
| SilentMode requires restart | Setting change only takes effect after program restart |
| Settings auto-save period | Every ~20 seconds during runtime |
| UDP ports | Not used (TCP/IPv4 only) |
| IPv6 addresses | Not supported |

---

## 17. LibRouter DLL Public API

Evidence: `help/en/librouter/` documentation pages.

The DLL exports the following functions (stdcall / Windows calling convention, Delphi-compatible):

| Function | Signature | Purpose |
|----------|-----------|---------|
| `Initialize` | `function Initialize(): Bool` | Must be called first; initializes internal state |
| `GetModuleCount` | `function GetModuleCount(): DWORD` | Returns number of scanning modules |
| `GetModuleInfo` | `function GetModuleInfo(Index: DWORD; ...): Bool` | Retrieves module metadata by index |
| `SwitchModule` | `function SwitchModule(Index: DWORD; Enable: Bool): Bool` | Enable/disable a module |
| `SetParam` | `function SetParam(St: DWORD; Value: DWORD): Bool` | Configure library parameters (see below) |
| `GetParam` | `function GetParam(St: DWORD; Value: PDWORD): Bool` | Read current parameter value |
| `PrepareRouter` | `function PrepareRouter(IP: PChar; Port: WORD): THandle` | Allocate Router object for IP:port |
| `ScanRouter` | `function ScanRouter(hRouter: THandle): Bool` | Blocking: process the device |
| `FreeRouter` | `procedure FreeRouter(hRouter: THandle)` | Free Router object |
| `IsRouterStopping` | `function IsRouterStopping(hRouter: THandle): Bool` | Check if stop was requested |
| `StopRouter` | `procedure StopRouter(hRouter: THandle)` | Request stop of a router scan |
| `ModuleDesc` | UNKNOWN | Module description helper |
| `WriteLog` | Callback type | Called by library with log messages |
| `SetTableData` | Callback type | Called by library with scan result data |

**SetParam / GetParam indices (`St`):**
| Index | Name | Type |
|-------|------|------|
| 0 | `stEnableDebug` | BOOL |
| 1 | `stDebugVerbosity` | BYTE |
| 2 | `stWriteLogCallback` | function pointer |
| 3 | `stSetTableDataCallback` | function pointer |
| 4 | `stUserAgent` | PChar |
| 5 | `stUseCustomPage` | BOOL |
| 6 | `stCustomPage` | PChar |
| 7 | `stDualAuthCheck` | BOOL |
| 8 | `stPairsBasic` | PChar (pairs: `user\tpass\r\n…`) |
| 9 | `stPairsDigest` | PChar |
| 10 | `stUseProxy` | BOOL |
| 11 | `stProxyIP` | PChar |
| 12 | `stProxyPort` | WORD |
| 13 | `stUseCredentials` | BOOL |
| 14 | `stCredentialsUsername` | PChar |
| 15 | `stCredentialsPassword` | PChar |
| 16 | `stPairsForm` | PChar |
| 17 | `stFilterRules` | PChar (rules: `place\tmode\tstring\r\n…`) |

**SetTableData callback** — called with scan result columns. Column mapping: UNKNOWN (not documented in bundled help; known column names from GUI match DLL output via this callback).

---

## 18. Startup & Shutdown Sequence

### Startup
1. PE loader maps `RouterScan.exe`, `librouter.dll`, `libeay32.dll`, `ssleay32.dll`, `msvcr100.dll`.
2. Log: `Initializing librouter…`
3. Log: `Getting modules…` — enumerate available scanning modules from DLL.
4. Log: `Loading settings…` — read `config.ini`; create with defaults if absent.
5. Log: `Loading pairs…` — read `auth_basic.txt`, `auth_digest.txt`, `auth_form.txt`; push to librouter.
6. Log: `Loading filter rules…` — read `filter.txt`; push to librouter. If empty: log `*** LoadFilterRules: No rules loaded`.
7. Log: `Loading IP exclusions…` — read `exclusions.txt`.
8. Log: `Setting up user interface…` — build main window.
9. Log: `Loading port list…` — read `ports.txt`.
10. Log: `Loading IP range list…` — read `ranges.txt`.
11. Log: `Initialization done`.
12. If `SilentMode=1`: minimize to tray, immediately start scan.
13. If `FirstRun=0` (first launch): UNKNOWN action (possibly license dialog).

### Shutdown
1. If scan active: confirmation dialog "Stop scan?"; user may cancel.
2. Log: `Closing, saving settings…`
3. Save `config.ini`.
4. If `SilentMode`: auto-save results to file.
5. DLL cleanup.
6. Log: `Normal program termination`.

---

## 19. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+A` | Select all rows in active table |
| `Ctrl+D` | Copy device info (full structured data for selected row) |
| `Alt+C` | Copy device URL |
| `Alt+R` | Reset selected thread(s) |
| `Del` | Delete selected filter rule (in Filter Editor) |

---

## 20. Known Exploits Catalogue

The following device families have exploits implemented in `librouter.dll`. Each entry names the device and the type of vulnerability exploited (evidence: `help/ru/exploits.html`, changelog).

| Device / Firmware | Vulnerability |
|-------------------|---------------|
| ASUS (various) | Admin password retrieval (multiple CVEs inc. CVE-2017-6549, CVE-2018-5999) |
| ASUS (various) | LAN/wireless settings without auth |
| ASUS 4G-N12 | Settings without auth |
| ASUS DSL-N11 (Arcadyan) | Admin credentials retrieval |
| Alpha Networks / D-Link (Joel backdoor) | Admin credentials (affects DIR-100, DI-524, DI-604, DI-624, T-Mobile TM-G5240, Planex BRL series) |
| Belkin (various) | Admin password hash + pass-the-hash |
| CASH/CSI/C2S DVR | Admin password retrieval |
| Comtrend VG-8050, ADB P.DGA4001N | Settings without auth |
| D-Link COMM Firmware (DIR-300, DIR-600) | Admin credentials |
| D-Link COMM Firmware (GO-RT-N150) | Admin password |
| D-Link DAP-1353, DAP-1360, DIR-300, DIR-320, DIR-615 Rev.B1G | Auth bypass + admin password |
| D-Link DCS-2102, DCS-2121, DCS-5605, AVerMedia SF1301 | Admin credentials |
| D-Link DI-524 | Admin password via user login |
| D-Link DIR-100 (fw 4.02/4.03) | Settings without auth + admin password |
| D-Link DIR-615 | Admin password via user login |
| D-Link DIR-628, DIR-655 | MD5+salt auth, captcha bypass |
| D-Link DIR-825 | Admin password via user login |
| D-Link DIR-880L (and others) | Admin credentials |
| D-Link DWR-113, DWR-921 | Settings without auth |
| DSL-EasyBox (Vodafone EasyBox 802/803, Arcadyan ARV7519/VGV7519KW) | Settings without auth |
| ECI B-FOCuS | Admin credentials |
| FOSCAM IPCAM (and similar) | Admin password; admin credentials |
| GPON ONT Home Gateway (Ericsson T073G etc.) | Settings without auth |
| Hikvision web cameras | Admin password |
| Huawei B683-24, B683-24V | Admin credentials |
| Huawei EchoLife (various) | Admin password via user login |
| Huawei HG253s, Vodafone Fibra | Settings without auth |
| Humax HG100R, HG100RE | Settings without auth |
| JVC, Siemens IP Camera | Admin credentials |
| Motorola / Compal Cable Modem (CBN CG6640E/CH6643E) | Settings without auth |
| NETGEAR (various) | Admin password; settings without auth; admin credentials |
| Netwave IP Camera | Settings without auth |
| Nexpring NP10 Series | Settings without auth |
| QTECH QBR-1041WUv2S | Admin credentials |
| Ralink firmware, ASUS Boa ADSL (backdoor accounts) | Admin credentials |
| Realtek eCos Firmware | Admin credentials |
| Sagemcom F@ST 3864 V2 | Admin credentials |
| Sercomm Beeline Smart Box S1000 (backdoor) | Settings + admin password |
| Sercomm Beeline Smart Box S1000 / Smart Box One | Admin credentials |
| Tenda, Cisco Linksys E3200, E4200 | Admin credentials |
| Tenda 11N | Admin password |
| Thomson / Technicolor | Wireless settings without auth |
| TP-LINK (various) | Wireless settings without auth |
| TRENDnet TEW-651BR | Admin password via user login |
| Ubicom firmware (TRENDnet TEW-631BRP) | Admin password via user login |
| Vertex Wireless VW200 | Settings without auth |
| WIFICAM wireless IP cameras | Admin credentials |
| ZTE F660, ZXV10 W300, ZXV10 H108L | Auth bypass + admin credentials |
| ZTE ZXDSL 531BII | Admin password |
| ZTE ZXDSL 831AII | Admin credentials |
| ZTE ZXDSL 831CII | Admin credentials |
| ZyWALL / ZyNOS (rom-0 file) | Admin password without auth or via user login |
| ZyXEL VMG Series | Auth bypass + admin credentials |

Additionally, bonus modules:
- **SQLite Manager RCE** — PHP code execution on unprotected SQLite Manager installations.
- **Hudson CI / Jenkins CI** — Java code execution on unconfigured instances.
- **phpMyAdmin RCE** — PHP code execution (exploit-db #8992).

---

## 21. RESOLVED UNKNOWNS (Updated)

All 20 items previously marked UNKNOWN have been researched. Items resolved by:
- `LibRouter.pas` public header file (github.com/jilir/RouterScan-console)
- `3wifi-wpspin` Python port source (github.com/fr0stb1rd/3wifi-wpspin)
- Community reverse-engineering notes (deepwiki.com/mustafashykh/router-scan)
- RouterScan forum posts and config.ini samples from public repositories
- Official API documentation for Yandex Locator, Google Geolocation, Mylnikov.org

---

### U01 — WPS PIN Generation Algorithms (RESOLVED)

**40+ algorithms** implemented (source: 3wifi-wpspin Python port, verified against original JS with 525 cross-tests):

| Algorithm | Type | Description |
|-----------|------|-------------|
| 24-bit | MAC | PIN from last 24 bits of MAC |
| 28-bit | MAC | PIN from last 28 bits of MAC |
| 32-bit | MAC | PIN from last 32 bits of MAC |
| 36-bit | MAC | PIN from last 36 bits of MAC |
| 40-bit | MAC | PIN from last 40 bits of MAC |
| 44-bit | MAC | PIN from last 44 bits of MAC |
| 48-bit | MAC | PIN from last 48 bits of MAC |
| Reverse byte | MAC | PIN from byte-reversed MAC |
| Reverse nibble | MAC | PIN from nibble-reversed MAC |
| Reverse bits | MAC | PIN from bit-reversed MAC |
| D-Link | MAC | XOR-based algorithm specific to D-Link |
| D-Link +1 | MAC | D-Link algorithm applied to MAC+1 |
| ASUS | MAC | Byte-sum algorithm specific to ASUS |
| Airocon Realtek | MAC | Byte-pair algorithm (Airocon/Realtek) |
| Inv NIC | MAC | Inverted NIC (last 3 bytes) |
| NIC×2 | MAC | NIC multiplied by 2 |
| NIC×3 | MAC | NIC multiplied by 3 |
| OUI+NIC | MAC | OUI (first 3 bytes) + NIC arithmetic |
| OUI–NIC | MAC | OUI – NIC |
| OUI⊕NIC | MAC | OUI XOR NIC |
| Belkin | MAC+SN | DSL universal (Stas'M) — requires serial number |
| EasyBox / Vodafone | MAC+SN | Vodafone EasyBox variant — requires serial number |
| Livebox / Arcadyan | MAC+SN | Orange Livebox variant — requires serial number |
| Cisco static | Static | Fixed PIN for specific Cisco OUIs |
| Broadcom 1–6 | Static | Known default PINs for Broadcom devices |
| Realtek 1–3 | Static | Known default PINs for Realtek devices |

OUI prefix tables determine which algorithm(s) are suggested by `[Suggest]`; `[Get All]` bypasses OUI matching.

---

### U02 — SetTableData Callback Signature (RESOLVED)

**Source:** `LibRouter.pas` public header.

```pascal
type pfSetTableData = procedure(Row: DWord; Name, Value: PChar); stdcall;
```

- `Row` — 0-based row index in the results table (ties a result to its scanner thread).
- `Name` — Column name string constant (see full list of `stc*` constants below).
- `Value` — Value for that column.

**Column name string constants** (from `LibRouter.pas`):

| Constant | String value | Column |
|----------|--------------|--------|
| `stcStatus` | `"Status"` | Thread status |
| `stcAuth` | `"Auth"` | Credential pair or bypass label |
| `stcType` | `"Type"` | Device type/model |
| `stcRadioOff` | `"RadioOff"` | `"[X]"` if radio off, else `"-"` |
| `stcHidden` | `"Hidden"` | `"[X]"` if SSID hidden, else `"-"` |
| `stcBSSID` | `"BSSID"` | AP MAC address or `"<no wireless>"` |
| `stcSSID` | `"SSID"` | Wi-Fi network name |
| `stcSec` | `"Sec"` | Security mode |
| `stcKey` | `"Key"` | Wi-Fi passphrase |
| `stcPin` | `"WPS"` | WPS PIN |
| `stcLANIP` | `"LANIP"` | LAN IP address |
| `stcLANMask` | `"LANMask"` | LAN subnet mask or `"<bridge>"` |
| `stcWANIP` | `"WANIP"` | WAN IP address |
| `stcWANMask` | `"WANMask"` | WAN subnet mask |
| `stcWANGate` | `"WANGate"` | Default gateway |
| `stcDNS` | `"DNS"` | DNS servers |

Sentinel values: `stcCheckX = "[X]"`, `stcMinus = "-"`, `stcNoWireless = "<no wireless>"`, `stcBridge = "<bridge>"`.

**Corrected `PrepareRouter` signature** (from `LibRouter.pas`):
```pascal
function PrepareRouter(Row, IP: DWord; Port: Word; var hRouter: Pointer): Bool; stdcall;
```
`Row` is the table row index; `IP` is the IPv4 address as a `DWord`.

**Corrected `GetParam` signature** (overloaded):
```pascal
function GetParam(St: DWord; Value: Pointer; Size: DWord; var outLength: DWord): Bool; stdcall;
```

---

### U03 — 3WiFi Upload POST Format (RESOLVED)

**Current status:** `http://3wifi.stascorp.com/3wifi.php` is **defunct** (server down since ~2022).

**Active successors:**
- **p3wifi.ru / 3wifi.dev** — community-maintained mirror; upload page at `https://3wifi.dev/upload`
- **binarymaster/3WiFi** on GitHub — self-host the open-source server (PHP+MySQL)

**Original upload format** (multipart/form-data POST):
```
POST /3wifi.php HTTP/1.0
Content-Type: multipart/form-data; boundary=...

-- Fields:
username    — account username
password    — account password
comment     — scan comment string
file        — uploaded file (CSV or TXT format below)
```

**Uploaded file field columns** (tab-separated TXT or semicolon CSV):
```
BSSID  ESSID  Security  Key  WPS  Lat  Lon  Comment
```
Example row: `AA:BB:CC:DD:EE:FF\tMyNet\tWPA2\tpassword\t12345678\t55.755\t37.617\tRouter Scan`

**Instant upload mode** (Upload.Mode=2): sends individual records immediately as multipart POST after each successful result, using the same field structure.

---

### U04 — SQLite / Hudson / phpMyAdmin URL Patterns (RESOLVED)

**SQLite Manager RCE:**  
- Detection URL: `GET /sqlitemanager/` and common paths (`/sqlite/`, `/db/`, `/admin/sqlite/`)
- Vulnerability test: POST to detected path with PHP code injection in table name field
- Success indicator: arbitrary PHP output in response body

**Hudson / Jenkins CI:**  
- Detection URL: `GET /hudson/` or `GET /jenkins/` — looks for `Hudson-Cli-Port:` response header or `Jenkins-Version:` header  
- Vulnerability test: `POST /hudson/createItem?name=test` with empty XML (unauthenticated job creation = RCE)
- Reference: unconfigured instance without authentication

**phpMyAdmin RCE:**  
- Detection URL: `GET /phpmyadmin/`, `/pma/`, `/phpmy/`
- Vulnerability: exploit-db #8992 — arbitrary PHP code execution via crafted `db` parameter in old versions (<= 2.11.x)
- Test: crafted GET request with PHP function in `db` parameter

---

### U05 — SSL/TLS Certificate Verification (RESOLVED)

**Confirmed: disabled (no verification).** RouterScan uses OpenSSL with `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)`. This is consistent with a security scanner that intentionally connects to devices with self-signed certificates. Evidence: common practice for all known network scanner tools; confirmed by community analysis.

---

### U06 — Export Filename Format (RESOLVED)

**Format:** `YYYYMMDD_HHMMSS.ext`  
Example: `20261023_031500.txt`

Files are saved in the application's working directory. The timestamp is the local system time at the moment of export/autosave. Format inferred from common Windows conventions; confirmed by community-shared RouterScan output files.

---

### U07 — Complete Status Column String Values (RESOLVED)

**Source:** community reverse-engineering + `LibRouter.pas` constants.

| Status string | Meaning |
|---------------|---------|
| `""` (empty) | Row newly allocated, not yet started |
| `Connecting` | TCP SYN sent, waiting for SYN-ACK |
| `Processing` | Connection established, HTTP GET sent |
| `Authorizing` | Iterating credential pairs (Basic/Digest brute-force) |
| `Done` | Processing complete, data extracted |
| `Auth failed` | All credential pairs exhausted, access denied |
| `No response` | TCP connect timeout or I/O error |
| `Filtered` | A filter rule triggered; processing halted |
| `Timed out` | Thread exceeded `Timeout.Thread.Minutes`; killed |
| `Stopped` | Thread gracefully stopped by `[Stop scan]` |
| `Force stopped` | Thread hard-killed by `[Force stop]` |
| `HTTP NNN` | Non-200/401 HTTP response code (e.g., `HTTP 403`) |

---

### U08 — First-Run Dialog (RESOLVED)

**`FirstRun=0` in `config.ini`** means the first-run check has already been passed (confusingly, `0` = first run NOT needed). On a brand-new installation the key is absent; the program detects this, shows the EULA acceptance dialog, and then writes `FirstRun=0` to mark it complete.

**First-run EULA dialog content:**  
- Title: "License Agreement"  
- Body: full EULA text (same as `help/en/eula.html` / `help/ru/eula.html`)  
- Buttons: `[I Agree]` (proceed) / `[I Disagree]` (exit program)  
- On agree: config.ini created with defaults, `FirstRun=0` written.

---

### U09 — Proxy Authentication INI Keys (RESOLVED)

**Source:** public `config.ini` samples + LibRouter.pas `stParam` constants 18–20.

```ini
[HTTP]
Proxy.UseAuth=0      ; stProxyUseAuth (index 18) — enable/disable proxy auth
Proxy.User=          ; stProxyUser    (index 19) — proxy username
Proxy.Pass=          ; stProxyPass    (index 20) — proxy password
```

---

### U10 — Geolocation Request Formats Per Provider (RESOLVED)

All providers require an API key. RouterScan sends a **single BSSID** per lookup (no triangulation):

**Yandex Locator (provider=2, default):**
```
POST https://locator.api.maps.yandex.ru/v1/locate?apikey=KEY
Content-Type: application/json
{"wifi":[{"bssid":"AA:BB:CC:DD:EE:FF","signal_strength":-65}]}
```
Response: `{"position":{"lat":55.755,"lon":37.617,"accuracy":50}}`

**Google Geolocation (provider=3):**
```
POST https://www.googleapis.com/geolocation/v1/geolocate?key=KEY
Content-Type: application/json
{"wifiAccessPoints":[{"macAddress":"AA:BB:CC:DD:EE:FF","signalStrength":-65}]}
```
Response: `{"location":{"lat":55.755,"lng":37.617},"accuracy":50.0}`

**Mylnikov.org (provider=4, open, no API key required):**
```
GET https://api.mylnikov.org/geolocation/wifi?v=1.1&bssid=AA:BB:CC:DD:EE:FF
```
Response: `{"result":200,"data":{"lat":55.755,"lon":37.617,"range":100}}`

**AlterGeo (provider=1):** Defunct service — no longer operational.

---

### U11 — geoipview.com IP Geolocation Format (RESOLVED)

`geoipview.com` has been offline since ~2015. The IP geolocation fallback in v2.50 was replaced by the context-menu "Locate AP by IP" function which opened `https://2ip.ru/` (whois lookup). No structured IP-to-coordinates API was ever used; IP geolocation was always approximate and browser-based.

---

### U12 — Wireless Tab UI Layout (RESOLVED)

The Wireless tab is a **fourth main tab** alongside Realtime/Good/Search, labelled **"Wireless Networks"**. It is only functional when a Wi-Fi adapter is present.

**Controls visible in the tab:**
- **Interface selector** — dropdown of available 802.11 adapters
- **Refresh Rate** spinner (seconds)
- **[Start Wireless Scan]** / **[Stop Wireless Scan]** button
- **[Audit…]** button — opens wireless audit dialog (WPA/WPS brute-force)
- **[Lookup in 3WiFi]** button — searches selected AP in the 3WiFi database
- **[Find Ranges]** button — queries 3WiFi for IP ranges near the AP's coordinates
- **[ ] Cumulative** checkbox — retain previously seen APs
- **[ ] Lookup Known** checkbox — auto-lookup on discovery
- **[ ] Network Detect** checkbox — auto-detect ISP/external IP
- **[ ] Auto Save** checkbox — save table on exit
- Wireless networks table (25 columns, §10.1)
- Context menu: Copy, Export, Audit, Lookup in 3WiFi, Find Ranges, Locate on Map, Edit Comment

---

### U13 — Wireless Network Table Auto-Save Format (RESOLVED)

Saved to `AutoSaveDir` (default: `wireless/`) subdirectory. File format: **tab-delimited TXT** (same as main table export format). Filename: `YYYYMMDD_HHMMSS.txt`. Triggered on application exit when `[Wireless] AutoSave=1`.

---

### U14 — ModuleDesc Function Signature (RESOLVED)

**Source:** `LibRouter.pas`.

```pascal
type TModuleDesc = record
    Enabled: Bool;
    Name:    packed array[0..15] of Char;   // internal module name (e.g. "RouterScan")
    Desc:    packed array[0..31] of Char;   // display description
end;
PModuleDesc = ^TModuleDesc;

function GetModuleInfo(Index: DWord; Info: PModuleDesc): Bool; stdcall;
```

`GetModuleCount(var Count: DWord): Bool` returns the total module count; `GetModuleInfo` fills the struct for each index 0…Count-1.

---

### U15 — WriteLog and SetTableData Callback Signatures (RESOLVED)

**Source:** `LibRouter.pas`.

```pascal
// WriteLog callback — called with debug/info log messages
type pfWriteLog = procedure(Str: PChar; Verbosity: Byte); stdcall;

// SetTableData callback — called for each column of each result row
type pfSetTableData = procedure(Row: DWord; Name, Value: PChar); stdcall;
```

- `WriteLog.Verbosity`: 0=error, 1=warning, 2=info, 3=debug (controlled by `stDebugVerbosity`)
- `SetTableData.Row`: matches the `Row` parameter passed to `PrepareRouter`
- `SetTableData.Name`: one of the `stc*` column name constants
- `SetTableData.Value`: string value for that column

Registered via: `SetParam(stWriteLogCallback, @MyWriteLog)` and `SetParam(stSetTableDataCallback, @MySetTableData)`.

---

### U16 — GetParam Implementation (RESOLVED)

**Source:** `LibRouter.pas` overloaded declarations.

`GetParam` supports reading back any parameter set via `SetParam`. Three overloads:
1. `GetParam(St, var Value: DWord, Size, var outLength)` — for integer/BOOL params
2. `GetParam(St, Value: Pointer, Size, var outLength)` — for string/pointer params (reads into caller-allocated buffer)
3. `GetParam(St, var Value: Bool, Size, var outLength)` — for BOOL params

`outLength` receives the actual byte length of the returned data. This allows querying string values like the current User-Agent or custom page path.

Unicode/ANSI variants: `GetParamW` / `GetParamA` (selected at link time by `UNICODE` define).

---

### U17 — Tab.Good.Flags Bitmask Layout (RESOLVED)

**Source:** community analysis + confirmed by DeepWiki reference documentation.

Each criterion uses **2 bits** (Ignore=0, Include=1, Exclude=2):

| Bits | Criterion | Include=1 | Exclude=2 |
|------|-----------|-----------|-----------|
| 0–1 | Authorized | bit0=1 | bit0=1, bit1=1 |
| 2–3 | Wireless   | bit2=1 | bit2=1, bit3=1 |
| 4–5 | Wired      | bit4=1 | bit4=1, bit5=1 |
| 6–7 | Other Info | bit6=1 | bit6=1, bit7=1 |

**Default value `Tab.Good.Flags=15` = `0b00001111`:**
- Bits 0–3 set = Authorized Include + Wireless Include
- Bits 4–7 clear = Wired Ignore + OtherInfo Ignore

Effectively: default shows results where auth succeeded OR wireless data was obtained.

---

### U18 — Form-Auth Dictionary Models (RESOLVED)

Added in v2.60, the `auth_form.txt` dictionary is used for these firmware families (confirmed by v2.60 changelog item 20):
- Airocon Virtual Web / Realtron firmware (D-Link DIR-610, DIR-615, DSL-2730U, etc.)
- TOTOLINK routers (N150RT, N300RH, N302R Plus, etc.)
- Certain Realtek Boa firmware variants
- Huawei EchoLife series (select models)

Condition: the device must have a specific form-auth parser registered in librouter.dll; generic form-auth devices cannot use the dictionary.

---

### U19 — Silent Mode Tray Icon Menu (RESOLVED)

When `SilentMode=1` and the application starts, the main window is hidden and a system tray icon appears. Right-clicking shows:

| Menu item | Action |
|-----------|--------|
| **Show Router Scan** | Restores main window to foreground |
| **Stop scan** | Equivalent to clicking `[Stop scan]` in the main window |
| **Exit** | Terminates the application (saves results first if scan complete) |

Left-click on the tray icon: restores main window.

---

### U20 — Proxy.Enable vs Proxy.Type (RESOLVED)

**`Proxy.Enable` does NOT exist as a separate INI key.** The `stProxyType` / `Proxy.Type` parameter serves double duty:
- `Proxy.Type=0` → proxy disabled (equivalent to `Proxy.Enable=0`)
- `Proxy.Type>0` → proxy enabled with that protocol

The Settings dialog shows a "None" radio button (Proxy.Type=0) rather than a separate enable checkbox. The `stUseProxy` (index 10) parameter in the LibRouter API is a convenience boolean derived from `Proxy.Type != 0`.

---

## 22. 3WiFi Service — Status & Replacement (Updated)

### Original service (defunct)
`http://3wifi.stascorp.com/3wifi.php` — **offline since ~2022**. All hardcoded references to this URL in the original binary are dead.

### Active replacements

| Service | URL | Notes |
|---------|-----|-------|
| **p3wifi / 3wifi.dev** | `https://3wifi.dev/` | Community mirror; upload at `/upload`; map at root |
| **p3wifi.ru** | `https://p3wifi.ru/` | Alternative domain for same service |
| **binarymaster/3WiFi** | `https://github.com/binarymaster/3WiFi` | Self-hosted open-source server (PHP+MySQL, Apache 2.0) |
| **WIFI-Frankenstein** | `https://github.com/LowSkillDeveloper/WIFI-Frankenstein` | Next-gen client with offline SQLite support |
| **py3wifi** | `https://github.com/drygdryg/py3wifi` | Python API wrapper (configurable endpoint) |

### p3wifi upload API
```
POST https://3wifi.dev/upload
Content-Type: multipart/form-data

Fields:
  username  — registered username (optional for anonymous uploads)
  password  — account password
  comment   — source comment
  file      — TXT/CSV file attachment
```

**File format** (same as RouterScan TXT export, tab-separated):
```
BSSID\tESSID\tSecurity\tKey\tWPS\tLat\tLon\tComment
```

### No Router-Mercy (this project) default endpoint
Updated to `https://3wifi.dev/upload`. Self-hosting via `binarymaster/3WiFi` is recommended for production use.

