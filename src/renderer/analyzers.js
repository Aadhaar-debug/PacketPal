'use strict';
/*
  PacketStore: ingests parsed packets and maintains the live, categorized
  state that every PacketPal tab renders from.

  Design notes / responsible-use:
  - The "Exposed Logins" tab is a DEFENSIVE detector. It flags when a service
    on the monitored network transmits credentials WITHOUT encryption, so the
    user learns what is exposed and can fix it. PacketPal deliberately does NOT
    store or display captured password values — only that an exposure happened,
    on which protocol, and between which endpoints.
*/
(function (global) {
  const C = global.Catalog;

  const MAX_PACKETS = 20000;      // in-memory cap for the traffic table
  const MAX_EVENTS = 1000;        // cap per event list

  // Highest-layer protocol -> friendly label.
  const PROTO_LABEL = {
    tls: 'HTTPS / TLS', ssl: 'HTTPS / TLS', http: 'HTTP (web)', http2: 'HTTP/2',
    dns: 'DNS', mdns: 'mDNS', quic: 'QUIC', tcp: 'TCP', udp: 'UDP',
    arp: 'ARP', icmp: 'ICMP (ping)', icmpv6: 'ICMPv6', dhcp: 'DHCP',
    bootp: 'DHCP', tftp: 'TFTP', ftp: 'FTP', 'ftp-data': 'FTP data',
    telnet: 'Telnet', ssh: 'SSH', smb2: 'SMB', nbns: 'NetBIOS', ntp: 'NTP',
    sip: 'SIP (VoIP)', rtp: 'RTP (media)', tls13: 'HTTPS / TLS',
  };

  function isPrivateIP(ip) {
    if (!ip) return false;
    if (ip.indexOf(':') >= 0) { // IPv6
      const l = ip.toLowerCase();
      return l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l === '::1';
    }
    const p = ip.split('.').map(Number);
    if (p.length !== 4) return false;
    if (p[0] === 10) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 127) return true;
    return false;
  }

  function highestProto(protocols) {
    if (!protocols) return '';
    const parts = protocols.split(':');
    for (let i = parts.length - 1; i >= 0; i--) {
      const t = parts[i];
      if (t && t !== 'ethertype' && t !== 'eth' && t !== 'data') return t;
    }
    return parts[parts.length - 1] || '';
  }

  function decodeBasicUser(authHeader) {
    // authHeader like 'Basic dXNlcjpwYXNz'. Return username ONLY; never the pass.
    try {
      const m = /^\s*Basic\s+([A-Za-z0-9+/=]+)/i.exec(authHeader);
      if (!m) return '';
      const decoded = atob(m[1]);
      const i = decoded.indexOf(':');
      return i >= 0 ? decoded.slice(0, i) : decoded;
    } catch (_) { return ''; }
  }

  class PacketStore {
    constructor() { this.reset(); }

    reset() {
      this.packets = [];
      this.totalPackets = 0;
      this.totalBytes = 0;
      this.startTime = null;

      this.devices = new Map();     // ip -> device
      this.credentials = [];        // exposure events (no secrets)
      this.anomalies = [];
      this.media = [];
      this.services = new Map();     // ip:port -> service

      this.protoCounts = new Map();  // friendly proto -> count (for filters)
      this.hostCounts = new Map();   // external host/domain -> count

      // detector state
      this._scan = new Map();        // srcIP -> {ports:Set, first, flagged}
      this._arp = new Map();         // ip -> mac
      this._arpFlagged = new Set();
      this._credSeen = new Set();    // dedupe key
      this._mediaSeen = new Set();
    }

    _touchDevice(ip, mac, t, len) {
      if (!ip) return null;
      let d = this.devices.get(ip);
      if (!d) {
        d = {
          ip, mac: mac || '', vendor: mac ? C.vendorForMac(mac) : '',
          hostname: '', packets: 0, bytes: 0,
          firstSeen: t, lastSeen: t, local: isPrivateIP(ip),
        };
        this.devices.set(ip, d);
      }
      if (mac && !d.mac) { d.mac = mac; d.vendor = C.vendorForMac(mac); }
      d.packets++; d.bytes += len; d.lastSeen = t;
      return d;
    }

    _setHostname(ip, name) {
      if (!ip || !name) return;
      const d = this.devices.get(ip);
      if (d && !d.hostname) d.hostname = name;
    }

    _pushCapped(arr, item) {
      arr.push(item);
      if (arr.length > MAX_EVENTS) arr.shift();
    }

    _bump(map, key) {
      if (!key) return;
      map.set(key, (map.get(key) || 0) + 1);
    }

    ingest(p) {
      const t = parseFloat(p['frame.time_epoch']) || (Date.now() / 1000);
      const len = parseInt(p['frame.len'], 10) || 0;
      if (this.startTime === null) this.startTime = t;
      this.totalPackets++;
      this.totalBytes += len;

      const srcIP = p['ip.src'] || p['ipv6.src'] || '';
      const dstIP = p['ip.dst'] || p['ipv6.dst'] || '';
      const sPort = p['tcp.srcport'] || p['udp.srcport'] || '';
      const dPort = p['tcp.dstport'] || p['udp.dstport'] || '';

      this._touchDevice(srcIP, p['eth.src'], t, len);
      this._touchDevice(dstIP, p['eth.dst'], t, 0);

      const proto = highestProto(p['frame.protocols']);
      const friendly = PROTO_LABEL[proto] || (proto ? proto.toUpperCase() : 'Other');
      this._bump(this.protoCounts, friendly);

      const tags = [];
      if (isPrivateIP(srcIP) || isPrivateIP(dstIP)) tags.push('local');

      let info = '';

      // --- Hostnames (devices tab enrichment) ---
      if (p['dhcp.option.hostname']) this._setHostname(srcIP, p['dhcp.option.hostname']);
      if (p['nbns.name']) this._setHostname(srcIP, p['nbns.name'].replace(/<.*$/, '').trim());

      // --- DNS / mDNS ---
      if (p['dns.qry.name']) {
        info = 'Looked up: ' + p['dns.qry.name'];
        tags.push('dns');
        this._bump(this.hostCounts, p['dns.qry.name']);
      }

      // --- TLS (secure) ---
      const sni = p['tls.handshake.extensions_server_name'];
      if (sni) {
        info = 'Secure connection to ' + sni;
        tags.push('secure');
        this._bump(this.hostCounts, sni);
      }

      // --- HTTP (unencrypted web) ---
      if (p['http.host'] || p['http.request.method'] || p['http.content_type']) {
        tags.push('web', 'insecure-plain');
        if (p['http.request.method']) {
          info = p['http.request.method'] + ' ' + (p['http.host'] || '') + (p['http.request.uri'] || '');
        } else if (p['http.host']) {
          info = 'HTTP ' + p['http.host'];
        }
        if (p['http.host']) this._bump(this.hostCounts, p['http.host']);
      }

      // --- Media (images / video on the wire) ---
      this._detectMedia(p, t, srcIP, tags);

      // --- Cleartext credential exposure (defensive) ---
      this._detectCredentials(p, t, srcIP, dstIP, tags);

      // --- Open ports / services (SYN-ACK => listening) ---
      this._detectService(p, srcIP, sPort);

      // --- Anomalies ---
      this._detectPortScan(p, t, srcIP, dstIP, dPort);
      this._detectArp(p, t);

      // --- ARP info line ---
      if (proto === 'arp' && !info) {
        info = p['arp.opcode'] === '1'
          ? `Who has ${p['arp.dst.proto_ipv4'] || '?'}? (ARP)`
          : `${p['arp.src.proto_ipv4'] || '?'} is at ${p['arp.src.hw_mac'] || '?'}`;
      }
      if (!info) {
        info = `${friendly}  ${srcIP || p['eth.src']}${sPort ? ':' + sPort : ''} → ${dstIP || p['eth.dst']}${dPort ? ':' + dPort : ''}`;
      }

      // --- lightweight record for the traffic table + filtering ---
      const rec = {
        n: this.totalPackets, t, len, proto: friendly,
        src: srcIP || p['eth.src'] || '', dst: dstIP || p['eth.dst'] || '',
        sport: sPort, dport: dPort, info, tags,
      };
      this.packets.push(rec);
      if (this.packets.length > MAX_PACKETS) this.packets.shift();
    }

    _detectMedia(p, t, srcIP, tags) {
      const ct = (p['http.content_type'] || '').toLowerCase();
      const uri = (p['http.request.uri'] || '').toLowerCase();
      let kind = '';
      if (ct.startsWith('image/')) kind = 'image';
      else if (ct.startsWith('video/')) kind = 'video';
      else if (/\.(jpg|jpeg|png|gif|webp|bmp|svg)(\?|$)/.test(uri)) kind = 'image';
      else if (/\.(mp4|webm|mov|avi|mkv|m3u8|ts)(\?|$)/.test(uri)) kind = 'video';
      if (!kind) return;
      const host = p['http.host'] || '';
      const key = kind + '|' + host + '|' + uri.slice(0, 80);
      if (this._mediaSeen.has(key)) return;
      this._mediaSeen.add(key);
      tags.push('media');
      this._pushCapped(this.media, {
        t, kind, contentType: ct || ('(' + kind + ' by file type)'),
        host, uri: p['http.request.uri'] || '', src: srcIP,
      });
    }

    _detectCredentials(p, t, srcIP, dstIP, tags) {
      const push = (ev) => {
        const key = ev.protocol + '|' + srcIP + '|' + dstIP + '|' + (ev.username || '') + '|' + ev.kind;
        if (this._credSeen.has(key)) return;
        this._credSeen.add(key);
        tags.push('exposed-login');
        this._pushCapped(this.credentials, ev);
      };

      // HTTP Authorization header sent over plain HTTP (we only ever see this
      // field when the traffic was NOT encrypted).
      if (p['http.authorization']) {
        const user = decodeBasicUser(p['http.authorization']);
        push({
          t, protocol: 'HTTP', kind: 'auth-header',
          endpoints: `${srcIP} → ${dstIP}${p['http.host'] ? ' (' + p['http.host'] + ')' : ''}`,
          username: user,
          summary: 'Login sent over unencrypted HTTP' + (user ? ` for user “${user}”` : ''),
        });
      }
      // FTP
      if (p['ftp.request.command'] === 'USER') {
        push({ t, protocol: 'FTP', kind: 'ftp-user',
          endpoints: `${srcIP} → ${dstIP}`, username: p['ftp.request.arg'] || '',
          summary: `FTP username “${p['ftp.request.arg'] || ''}” sent in cleartext` });
      }
      if (p['ftp.request.command'] === 'PASS') {
        push({ t, protocol: 'FTP', kind: 'ftp-pass',
          endpoints: `${srcIP} → ${dstIP}`, username: '',
          summary: 'FTP password sent in cleartext (value hidden by PacketPal)' });
      }
      // Telnet
      if (p['telnet.data']) {
        push({ t, protocol: 'Telnet', kind: 'telnet',
          endpoints: `${srcIP} → ${dstIP}`, username: '',
          summary: 'Telnet session is fully unencrypted — anything typed is visible' });
      }
      // POP3 / IMAP plaintext login
      if (p['pop.request.command'] && /user|pass/i.test(p['pop.request.command'])) {
        push({ t, protocol: 'POP3', kind: 'pop',
          endpoints: `${srcIP} → ${dstIP}`, username: '',
          summary: 'Email (POP3) login sent without encryption' });
      }
      if (p['imap.request'] && /login/i.test(p['imap.request'])) {
        push({ t, protocol: 'IMAP', kind: 'imap',
          endpoints: `${srcIP} → ${dstIP}`, username: '',
          summary: 'Email (IMAP) login sent without encryption' });
      }
    }

    _detectService(p, srcIP, sPort) {
      // A SYN+ACK means srcIP:srcPort accepted a connection => it is listening.
      if (p['tcp.flags.syn'] === '1' && p['tcp.flags.ack'] === '1' && srcIP && sPort) {
        const key = srcIP + ':' + sPort;
        if (!this.services.has(key)) {
          this.services.set(key, {
            ip: srcIP, port: sPort, service: C.serviceName(sPort),
            local: isPrivateIP(srcIP),
          });
        }
      }
    }

    _detectPortScan(p, t, srcIP, dstIP, dPort) {
      // Many SYN (without ACK) to many distinct ports from one source = scan.
      if (!(p['tcp.flags.syn'] === '1' && p['tcp.flags.ack'] === '0')) return;
      if (!srcIP || !dPort) return;
      let s = this._scan.get(srcIP);
      if (!s || (t - s.first) > 10) s = { ports: new Set(), first: t, flagged: false, dst: dstIP };
      s.ports.add(dPort);
      this._scan.set(srcIP, s);
      if (!s.flagged && s.ports.size >= 15) {
        s.flagged = true;
        this._pushCapped(this.anomalies, {
          t, type: 'port-scan', severity: 'high',
          title: 'Possible port scan',
          detail: `${srcIP} probed ${s.ports.size}+ different ports on ${s.dst || 'a device'} in a few seconds. This is how an attacker (or a scanning tool) hunts for open doors.`,
        });
      }
    }

    _detectArp(p, t) {
      const ip = p['arp.src.proto_ipv4'];
      const mac = p['arp.src.hw_mac'];
      if (!ip || !mac) return;
      const prev = this._arp.get(ip);
      if (prev && prev !== mac && !this._arpFlagged.has(ip)) {
        this._arpFlagged.add(ip);
        this._pushCapped(this.anomalies, {
          t, type: 'arp-spoof', severity: 'high',
          title: 'Possible ARP spoofing (man-in-the-middle)',
          detail: `The address ${ip} is now claimed by a different device (${mac}, was ${prev}). This can mean someone is trying to intercept traffic on your network.`,
        });
      }
      this._arp.set(ip, mac);
    }

    // Serializable snapshot for the UI (bounded sizes).
    snapshot() {
      const devices = Array.from(this.devices.values())
        .sort((a, b) => b.packets - a.packets);
      const services = Array.from(this.services.values())
        .sort((a, b) => (a.local === b.local ? 0 : a.local ? -1 : 1));
      const topProtocols = Array.from(this.protoCounts.entries())
        .sort((a, b) => b[1] - a[1]);
      const topHosts = Array.from(this.hostCounts.entries())
        .sort((a, b) => b[1] - a[1]).slice(0, 40);

      return {
        totalPackets: this.totalPackets,
        totalBytes: this.totalBytes,
        durationSec: this.startTime ? (this.packets.length ? (this.packets[this.packets.length - 1].t - this.startTime) : 0) : 0,
        counts: {
          devices: devices.length,
          credentials: this.credentials.length,
          anomalies: this.anomalies.length,
          media: this.media.length,
          services: services.length,
        },
        devices,
        credentials: this.credentials.slice().reverse(),
        anomalies: this.anomalies.slice().reverse(),
        media: this.media.slice().reverse(),
        services,
        topProtocols,
        topHosts,
      };
    }
  }

  global.Analyzers = { PacketStore, isPrivateIP };
})(window);
