'use strict';
/*
  PacketStore: ingests parsed packets and maintains the live, categorized
  state that every PacketPal tab renders from.

  Responsible-use: the "Exposed Logins" tab is a DEFENSIVE detector. It flags
  when a service transmits credentials WITHOUT encryption so the user can fix
  it, and deliberately never stores or displays captured password values.
*/
(function (global) {
  const C = global.Catalog;

  const MAX_PACKETS = 20000;
  const MAX_EVENTS = 1000;

  const PROTO_LABEL = {
    tls: 'HTTPS / TLS', ssl: 'HTTPS / TLS', http: 'HTTP (web)', http2: 'HTTP/2',
    dns: 'DNS', mdns: 'mDNS', quic: 'QUIC (fast web)', tcp: 'TCP', udp: 'UDP',
    arp: 'ARP', icmp: 'ICMP (ping)', icmpv6: 'ICMPv6', dhcp: 'DHCP', bootp: 'DHCP',
    tftp: 'TFTP', ftp: 'FTP', 'ftp-data': 'FTP data', telnet: 'Telnet', ssh: 'SSH',
    smb2: 'SMB', nbns: 'NetBIOS', ntp: 'NTP', sip: 'SIP (VoIP)', rtp: 'RTP (media)',
    ssdp: 'SSDP (discovery)', llmnr: 'LLMNR', igmp: 'IGMP', stun: 'STUN (calls)',
  };

  function isPrivateIP(ip) {
    if (!ip) return false;
    if (ip.indexOf(':') >= 0) {
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
  function isNoise(ip) { // broadcast / multicast / unspecified -> not a real device
    if (!ip) return true;
    if (ip === '255.255.255.255' || ip === '0.0.0.0') return true;
    if (/\.255$/.test(ip)) return true;                 // subnet broadcast
    const o = parseInt(ip, 10);
    if (o >= 224 && o <= 239) return true;              // IPv4 multicast
    if (ip.toLowerCase().startsWith('ff')) return true; // IPv6 multicast
    return false;
  }
  function isGroupMac(mac) { // broadcast / multicast MAC (not a single device)
    if (!mac || mac.length < 2) return true;
    const f = parseInt(mac.slice(0, 2), 16);
    return isNaN(f) || (f & 0x01) === 1;
  }
  function isV4(ip) { return /^\d+\.\d+\.\d+\.\d+$/.test(ip); }
  function isApple17(ip) { return /^17\.\d/.test(ip || ''); } // 17.0.0.0/8 is Apple
  function isPrivateMac(mac) {
    if (!mac || mac.length < 2) return false;
    const f = parseInt(mac.slice(0, 2), 16);
    return !isNaN(f) && (f & 0x02) && !(f & 0x01);
  }

  function highestProto(protocols) {
    if (!protocols) return '';
    const parts = protocols.split(':');
    for (let i = parts.length - 1; i >= 0; i--) {
      const t = parts[i];
      if (t && t !== 'ethertype' && t !== 'eth' && t !== 'data' && t !== 'ip' && t !== 'ipv6') return t;
    }
    return parts[parts.length - 1] || '';
  }

  function decodeBasicUser(authHeader) {
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
      this.lastTime = null;

      this.devices = new Map();
      this.credentials = [];
      this.anomalies = [];
      this.media = [];
      this.services = new Map();      // listening ports: ip:port -> {..}
      this.servicePorts = new Map();  // service-in-use: port -> {count, service}

      this.protoCounts = new Map();
      this.hostCounts = new Map();

      this._scan = new Map();
      this._arp = new Map();
      this._arpFlagged = new Set();
      this._credSeen = new Set();
      this._mediaSeen = new Set();
    }

    _touchDevice(ip, mac, t, vendorResolved) {
      if (!ip || isNoise(ip)) return null;
      const local = isPrivateIP(ip);
      // Local devices are keyed by MAC so one device's IPv4 + IPv6 merge into
      // a single entry. Internet servers share the router's MAC, so key by IP.
      const key = (local && mac && !isGroupMac(mac)) ? 'm:' + mac.toLowerCase() : 'i:' + ip;
      let d = this.devices.get(key);
      if (!d) {
        d = {
          key, ip, ips: new Set([ip]), mac: mac || '', vendor: '', hostname: '',
          userAgent: '', vendorClass: '', packets: 0, bytesIn: 0, bytesOut: 0,
          peers: new Set(), services: new Set(), firstSeen: t, lastSeen: t,
          local, appleHint: false, privateMac: isPrivateMac(mac),
        };
        this.devices.set(key, d);
      }
      d.ips.add(ip);
      // prefer an IPv4 private address as the one we display
      if (isV4(ip) && (!isV4(d.ip))) d.ip = ip;
      if (mac && !d.mac) { d.mac = mac; d.privateMac = isPrivateMac(mac); }
      const v = (vendorResolved || '').replace(/[.,]+$/, '').trim();
      if (v && !/^(icann|iana|ieee)\b/i.test(v) && !d.vendor) d.vendor = vendorResolved;
      if (!d.vendor && mac) { const vf = C.vendorForMac(mac); if (vf && vf !== 'Private address') d.vendor = vf; }
      d.lastSeen = t;
      return d;
    }

    _pushCapped(arr, item) { arr.push(item); if (arr.length > MAX_EVENTS) arr.shift(); }
    _bump(map, key) { if (key) map.set(key, (map.get(key) || 0) + 1); }

    ingest(p) {
      const t = parseFloat(p['frame.time_epoch']) || (Date.now() / 1000);
      const len = parseInt(p['frame.len'], 10) || 0;
      if (this.startTime === null) this.startTime = t;
      this.lastTime = t;
      this.totalPackets++;
      this.totalBytes += len;

      const srcIP = p['ip.src'] || p['ipv6.src'] || '';
      const dstIP = p['ip.dst'] || p['ipv6.dst'] || '';
      const sPort = p['tcp.srcport'] || p['udp.srcport'] || '';
      const dPort = p['tcp.dstport'] || p['udp.dstport'] || '';

      const srcDev = this._touchDevice(srcIP, p['eth.src'], t, p['eth.src.oui_resolved']);
      const dstDev = this._touchDevice(dstIP, p['eth.dst'], t, p['eth.dst.oui_resolved']);
      if (srcDev) { srcDev.packets++; srcDev.bytesOut += len; }
      if (dstDev) { dstDev.packets++; dstDev.bytesIn += len; }
      if (srcDev && dstIP && !isNoise(dstIP)) srcDev.peers.add(dstIP);
      if (dstDev && srcIP && !isNoise(srcIP)) dstDev.peers.add(srcIP);

      // behavioral device hints
      if (srcDev && isApple17(dstIP)) srcDev.appleHint = true;
      if (dstDev && isApple17(srcIP)) dstDev.appleHint = true;

      const proto = highestProto(p['frame.protocols']);
      const friendly = PROTO_LABEL[proto] || (proto ? proto.toUpperCase() : 'Other');
      this._bump(this.protoCounts, friendly);

      const tags = [];
      if (isPrivateIP(srcIP) || isPrivateIP(dstIP)) tags.push('local');
      let info = '';

      // hostnames
      if (p['dhcp.option.hostname'] && srcDev && !srcDev.hostname) srcDev.hostname = p['dhcp.option.hostname'];
      if (p['dhcp.option.vendor_class_id'] && srcDev && !srcDev.vendorClass) srcDev.vendorClass = p['dhcp.option.vendor_class_id'];
      if (p['nbns.name'] && srcDev && !srcDev.hostname) srcDev.hostname = p['nbns.name'].replace(/<.*$/, '').trim();
      if (p['http.user_agent'] && srcDev && !srcDev.userAgent) srcDev.userAgent = p['http.user_agent'];

      // DNS / mDNS
      const q = p['dns.qry.name'];
      if (q) {
        if (proto === 'mdns' || /\.local$/.test(q)) {
          if (srcDev && /companion-link|airplay|_raop|airdrop|_homekit|_sleep-proxy|_rdlink/i.test(q)) srcDev.appleHint = true;
          if (srcDev && /_googlecast|_androidtvremote/i.test(q)) srcDev.hostname = srcDev.hostname || 'Cast device';
          info = 'Local discovery: ' + q;
          tags.push('dns');
        } else {
          info = 'Looked up: ' + q;
          tags.push('dns');
          this._bump(this.hostCounts, q);
        }
      }

      const sni = p['tls.handshake.extensions_server_name'];
      if (sni) { info = 'Secure connection to ' + sni; tags.push('secure'); this._bump(this.hostCounts, sni); }

      if (p['http.host'] || p['http.request.method'] || p['http.content_type']) {
        tags.push('web', 'insecure-plain');
        if (p['http.request.method']) info = p['http.request.method'] + ' ' + (p['http.host'] || '') + (p['http.request.uri'] || '');
        else if (p['http.host']) info = 'HTTP ' + p['http.host'];
        if (p['http.host']) this._bump(this.hostCounts, p['http.host']);
      }

      this._detectMedia(p, t, srcIP, tags);
      this._detectCredentials(p, t, srcIP, dstIP, tags);
      this._detectService(p, srcIP, sPort);
      this._trackServiceUse(dPort, srcDev);
      this._detectPortScan(p, t, srcIP, dstIP, dPort);
      this._detectArp(p, t);

      if (proto === 'arp' && !info) {
        info = p['arp.opcode'] === '1'
          ? `Who has ${p['arp.dst.proto_ipv4'] || '?'}? (ARP)`
          : `${p['arp.src.proto_ipv4'] || '?'} is at ${p['arp.src.hw_mac'] || '?'}`;
      }
      if (!info) info = `${friendly}  ${srcIP || p['eth.src']}${sPort ? ':' + sPort : ''} → ${dstIP || p['eth.dst']}${dPort ? ':' + dPort : ''}`;

      const rec = {
        n: this.totalPackets, t, len, proto: friendly,
        src: srcIP || p['eth.src'] || '', dst: dstIP || p['eth.dst'] || '',
        smac: p['eth.src'] || '', dmac: p['eth.dst'] || '',
        sport: sPort, dport: dPort, info, tags,
      };
      this.packets.push(rec);
      if (this.packets.length > MAX_PACKETS) this.packets.shift();
    }

    _trackServiceUse(dPort, srcDev) {
      const n = parseInt(dPort, 10);
      if (!n || !C.PORT_SERVICES[n]) return; // only recognizable services, no ephemeral noise
      const name = C.serviceName(dPort);
      let s = this.servicePorts.get(n);
      if (!s) { s = { port: n, service: name, count: 0 }; this.servicePorts.set(n, s); }
      s.count++;
      if (srcDev) srcDev.services.add(name);
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
      this._pushCapped(this.media, { t, kind, contentType: ct || ('(' + kind + ' by file type)'), host, uri: p['http.request.uri'] || '', src: srcIP });
    }

    _detectCredentials(p, t, srcIP, dstIP, tags) {
      const push = (ev) => {
        const key = ev.protocol + '|' + srcIP + '|' + dstIP + '|' + (ev.username || '') + '|' + ev.kind;
        if (this._credSeen.has(key)) return;
        this._credSeen.add(key);
        tags.push('exposed-login');
        this._pushCapped(this.credentials, ev);
      };
      if (p['http.authorization']) {
        const user = decodeBasicUser(p['http.authorization']);
        push({ t, protocol: 'HTTP', kind: 'auth-header',
          endpoints: `${srcIP} → ${dstIP}${p['http.host'] ? ' (' + p['http.host'] + ')' : ''}`,
          username: user, summary: 'Login sent over unencrypted HTTP' + (user ? ` for user “${user}”` : '') });
      }
      if (p['ftp.request.command'] === 'USER') push({ t, protocol: 'FTP', kind: 'ftp-user', endpoints: `${srcIP} → ${dstIP}`, username: p['ftp.request.arg'] || '', summary: `FTP username “${p['ftp.request.arg'] || ''}” sent in cleartext` });
      if (p['ftp.request.command'] === 'PASS') push({ t, protocol: 'FTP', kind: 'ftp-pass', endpoints: `${srcIP} → ${dstIP}`, username: '', summary: 'FTP password sent in cleartext (value hidden by PacketPal)' });
      if (p['telnet.data']) push({ t, protocol: 'Telnet', kind: 'telnet', endpoints: `${srcIP} → ${dstIP}`, username: '', summary: 'Telnet session is fully unencrypted — anything typed is visible' });
      if (p['pop.request.command'] && /user|pass/i.test(p['pop.request.command'])) push({ t, protocol: 'POP3', kind: 'pop', endpoints: `${srcIP} → ${dstIP}`, username: '', summary: 'Email (POP3) login sent without encryption' });
      if (p['imap.request'] && /login/i.test(p['imap.request'])) push({ t, protocol: 'IMAP', kind: 'imap', endpoints: `${srcIP} → ${dstIP}`, username: '', summary: 'Email (IMAP) login sent without encryption' });
    }

    _detectService(p, srcIP, sPort) {
      if (p['tcp.flags.syn'] === '1' && p['tcp.flags.ack'] === '1' && srcIP && sPort) {
        const key = srcIP + ':' + sPort;
        if (!this.services.has(key)) this.services.set(key, { ip: srcIP, port: sPort, service: C.serviceName(sPort), local: isPrivateIP(srcIP) });
      }
    }

    _detectPortScan(p, t, srcIP, dstIP, dPort) {
      if (!(p['tcp.flags.syn'] === '1' && p['tcp.flags.ack'] === '0')) return;
      if (!srcIP || !dPort) return;
      let s = this._scan.get(srcIP);
      if (!s || (t - s.first) > 10) s = { ports: new Set(), first: t, flagged: false, dst: dstIP };
      s.ports.add(dPort);
      this._scan.set(srcIP, s);
      if (!s.flagged && s.ports.size >= 15) {
        s.flagged = true;
        this._pushCapped(this.anomalies, { t, type: 'port-scan', severity: 'high', title: 'Possible port scan',
          detail: `${srcIP} probed ${s.ports.size}+ different ports on ${s.dst || 'a device'} in a few seconds. This is how an attacker (or a scanning tool) hunts for open doors.` });
      }
    }

    _detectArp(p, t) {
      const ip = p['arp.src.proto_ipv4'], mac = p['arp.src.hw_mac'];
      if (!ip || !mac) return;
      const prev = this._arp.get(ip);
      if (prev && prev !== mac && !this._arpFlagged.has(ip)) {
        this._arpFlagged.add(ip);
        this._pushCapped(this.anomalies, { t, type: 'arp-spoof', severity: 'high', title: 'Possible ARP spoofing (man-in-the-middle)',
          detail: `The address ${ip} is now claimed by a different device (${mac}, was ${prev}). This can mean someone is trying to intercept traffic on your network.` });
      }
      this._arp.set(ip, mac);
    }

    snapshot() {
      const devices = Array.from(this.devices.values()).map((d) => {
        const id = C.identifyDevice(d);
        return {
          ip: d.ip, mac: d.mac, vendor: id.vendor || '', hostname: d.hostname,
          name: id.name, icon: id.icon, type: id.type, confidence: id.confidence,
          privateMac: d.privateMac, local: d.local, addresses: d.ips.size,
          packets: d.packets, bytes: d.bytesIn + d.bytesOut, bytesIn: d.bytesIn, bytesOut: d.bytesOut,
          peers: d.peers.size, services: Array.from(d.services).slice(0, 4),
          firstSeen: d.firstSeen, lastSeen: d.lastSeen,
        };
      }).sort((a, b) => (a.local === b.local ? b.packets - a.packets : (a.local ? -1 : 1)));

      const namedLocal = devices.filter((d) => d.local && d.confidence !== 'low');
      const services = Array.from(this.services.values());
      const servicesInUse = Array.from(this.servicePorts.values()).sort((a, b) => b.count - a.count).slice(0, 25);
      const distinctServices = new Set([...services.map((s) => s.service), ...servicesInUse.map((s) => s.service)]);

      return {
        totalPackets: this.totalPackets,
        totalBytes: this.totalBytes,
        durationSec: this.startTime ? (this.lastTime - this.startTime) : 0,
        counts: {
          devices: devices.filter((d) => d.local).length,
          credentials: this.credentials.length,
          anomalies: this.anomalies.length,
          media: this.media.length,
          services: distinctServices.size,
        },
        devices,
        namedLocal,
        credentials: this.credentials.slice().reverse(),
        anomalies: this.anomalies.slice().reverse(),
        media: this.media.slice().reverse(),
        services,
        servicesInUse,
        topProtocols: Array.from(this.protoCounts.entries()).sort((a, b) => b[1] - a[1]),
        topHosts: Array.from(this.hostCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 40),
      };
    }
  }

  global.Analyzers = { PacketStore, isPrivateIP };
})(window);
