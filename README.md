# 🐾 PacketPal

**Your network, in plain English.** PacketPal is a beginner-friendly face over
[Wireshark](https://www.wireshark.org/)'s capture engine (`tshark`). Wireshark is
incredibly powerful but overwhelming — walls of packets, cryptic filters, no
hand-holding. PacketPal keeps all that power underneath and puts a calm,
explain-as-you-go dashboard on top.

Press **Start watching** and PacketPal immediately begins sorting everything it
sees into friendly, self-updating tabs — each with a live counter.

![icon](build/icon.png)

## What the tabs do

| Tab | What it watches for |
| --- | --- |
| 👥 **Devices & Users** | Every gadget on the network — phone, laptop, TV, smart bulb — with a best-guess maker and name. |
| 🔑 **Exposed Logins** | Services that send credentials **without encryption** (plain HTTP, FTP, Telnet, old email). A defensive alarm so you can fix them. *PacketPal flags the exposure but never stores the actual passwords.* |
| ⚠️ **Anomalies** | Attack-shaped patterns: port scans (someone hunting for open doors) and ARP spoofing (a classic man-in-the-middle trick). |
| 🖼️ **Photos & Video** | Images and video crossing the wire **unencrypted**. (Encrypted sites stay private and won't appear.) |
| 🚪 **Open Doors** | Open ports / listening services on your devices, with a plain-language name for each. |
| 🌐 **All Traffic** | The full live feed in friendly language, with **filter buttons that generate themselves** as new kinds of traffic appear. |

## Responsible use

PacketPal is for **networks you own or are explicitly authorized to test** —
your home Wi-Fi, a lab, a network you've been hired to assess. Capturing other
people's traffic without permission is illegal in most places. The "Exposed
Logins" tab exists to help you *find and fix* insecure services, not to harvest
anyone's secrets — which is why it never stores captured passwords.

## Requirements

- macOS (Apple Silicon build provided)
- [Wireshark](https://www.wireshark.org/) / `tshark` — install with Homebrew:
  ```bash
  brew install wireshark
  ```

## One-time capture permission

macOS blocks packet capture until you install Wireshark's permission helper.
Run this once (it asks for your password), then reopen PacketPal:

```bash
brew install --cask wireshark-chmodbpf
```

PacketPal detects this automatically and shows you the exact command if it's
missing.

## Install (the easy way)

Download the latest **PacketPal.dmg** from the
[Releases](../../releases) page, open it, and drag PacketPal to Applications.

> It's an unsigned build, so the first time, **right-click the app → Open** and
> confirm. (Signing requires a paid Apple Developer ID.)

## Run from source

```bash
git clone https://github.com/Aadhaar-debug/PacketPal.git
cd PacketPal
npm install
npm start
```

## Build the .dmg yourself

```bash
npm run dist
# output lands in release/PacketPal-1.0.0-arm64.dmg
```

## How it works

```
tshark  ──(live, tab-separated fields)──▶  Electron main process
                                              │ batches packets (250ms)
                                              ▼
                                        Renderer (analyzers.js)
                                   sorts each packet into the tabs,
                                   builds counters + filter facets
```

No packets are ever sent anywhere — everything stays on your machine.

## Tech

Electron · `tshark` · vanilla JS (no framework) · `electron-builder`.

## License

MIT — see [LICENSE](LICENSE). Wireshark is a separate GPL-2.0 project that
PacketPal runs as an external tool; it is not bundled or modified here.
