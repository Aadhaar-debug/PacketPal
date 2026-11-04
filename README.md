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
| 👥 **Devices & Users** | Every gadget on the network, **named** — "iPhone", "Samsung TV", "Raspberry Pi" — from its maker (tshark's IEEE database), the name it announces, and how it behaves. Deduplicated by hardware address (one device = one entry, even with IPv4 + IPv6), with data sent/received and how many connections each has. |
| 🔑 **Logins** | **All** login-related activity: login pages opened, secure login services connected to (🔒 HTTPS), and any credentials seen. Anything **unencrypted** (🔓 plain HTTP, FTP, Telnet, old email) is flagged as risky. *Passwords are flagged but never stored.* |
| ⚠️ **Anomalies** | Anything that shouldn't happen on a home network: unencrypted web pages, insecure protocols (Telnet/FTP), risky services exposed to the internet (SMB/RDP/VNC), port scans, and ARP spoofing — colour-coded by severity. |
| 🖼️ **Photos & Video** | Images and video crossing the wire **unencrypted**. (Encrypted sites stay private and won't appear.) |
| 🚪 **Open Doors** | Open ports / listening services on your devices, with a plain-language name for each. |
| 🌐 **All Traffic** | The full live feed in friendly language. Every source and destination IP is **labelled with its domain name** (learned from DNS/HTTPS) so you see *who* each IP is, not just a number. **Filter buttons generate themselves** as traffic appears — including **one button per identified device**. |

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
