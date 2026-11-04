'use strict';

// The exact list of tshark fields PacketPal asks for, in order.
// Each packet line that tshark emits is tab-separated in EXACTLY this order,
// so the renderer/analyzers can read values by name via FIELD_INDEX.
const FIELDS = [
  'frame.number',
  'frame.time_epoch',
  'frame.len',
  'frame.protocols',
  'eth.src',
  'eth.dst',
  'eth.src.oui_resolved',
  'eth.dst.oui_resolved',
  'ip.src',
  'ip.dst',
  'ipv6.src',
  'ipv6.dst',
  'tcp.srcport',
  'tcp.dstport',
  'tcp.flags.syn',
  'tcp.flags.ack',
  'tcp.flags.reset',
  'udp.srcport',
  'udp.dstport',
  'dns.qry.name',
  'dns.a',
  'dns.aaaa',
  'http.host',
  'http.request.method',
  'http.request.uri',
  'http.user_agent',
  'http.authorization',
  'http.content_type',
  'http.response.code',
  'ftp.request.command',
  'ftp.request.arg',
  'telnet.data',
  'pop.request.command',
  'imap.request',
  'tls.handshake.extensions_server_name',
  'arp.src.proto_ipv4',
  'arp.src.hw_mac',
  'arp.opcode',
  'arp.dst.proto_ipv4',
  'dhcp.option.hostname',
  'dhcp.option.vendor_class_id',
  'nbns.name',
];

const FIELD_INDEX = {};
FIELDS.forEach((f, i) => { FIELD_INDEX[f] = i; });

// Build the `-e field` argument list for tshark.
function fieldArgs() {
  const args = [];
  for (const f of FIELDS) { args.push('-e', f); }
  return args;
}

// Turn a tab-separated tshark line into a plain object keyed by field name.
function parseLine(line) {
  const cols = line.split('\t');
  const p = {};
  for (let i = 0; i < FIELDS.length; i++) {
    p[FIELDS[i]] = cols[i] !== undefined ? cols[i] : '';
  }
  return p;
}

// Common TCP/UDP ports -> friendly service names, in plain language.
const PORT_SERVICES = {
  20: 'FTP data', 21: 'FTP (file transfer)', 22: 'SSH (secure shell)',
  23: 'Telnet (INSECURE remote login)', 25: 'SMTP (email sending)',
  53: 'DNS (domain lookups)', 67: 'DHCP', 68: 'DHCP',
  80: 'HTTP (web, unencrypted)', 110: 'POP3 (email, often plaintext)',
  111: 'RPC', 123: 'NTP (clock sync)', 137: 'NetBIOS name',
  138: 'NetBIOS datagram', 139: 'NetBIOS / SMB', 143: 'IMAP (email)',
  161: 'SNMP', 389: 'LDAP', 443: 'HTTPS (secure web)', 445: 'SMB (file sharing)',
  465: 'SMTPS (secure email)', 514: 'Syslog', 548: 'AFP (Apple file sharing)',
  587: 'SMTP (email submission)', 631: 'IPP (printing)', 636: 'LDAPS',
  993: 'IMAPS (secure email)', 995: 'POP3S (secure email)',
  1080: 'SOCKS proxy', 1433: 'MS SQL', 1521: 'Oracle DB', 1883: 'MQTT (IoT)',
  3306: 'MySQL database', 3389: 'RDP (remote desktop)', 5000: 'UPnP / dev server',
  5060: 'SIP (VoIP calls)', 5353: 'mDNS (Bonjour/local discovery)',
  5432: 'PostgreSQL', 5900: 'VNC (screen sharing)', 6379: 'Redis',
  8080: 'HTTP alt (web)', 8443: 'HTTPS alt', 9100: 'Printer (raw)',
  27017: 'MongoDB', 32400: 'Plex media server',
};

function serviceName(port) {
  const n = parseInt(port, 10);
  if (PORT_SERVICES[n]) return PORT_SERVICES[n];
  if (n >= 49152) return 'Dynamic / private port';
  return 'Port ' + n;
}

// A small, deliberately-partial map of MAC OUI prefixes -> vendor.
// Not a full IEEE database — just enough to make common devices recognizable.
const OUI = {
  '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0a:27': 'Apple',
  '00:0a:95': 'Apple', '00:1b:63': 'Apple', '00:1e:c2': 'Apple',
  '00:25:00': 'Apple', '3c:07:54': 'Apple', 'a4:5e:60': 'Apple',
  'ac:bc:32': 'Apple', 'f0:18:98': 'Apple', 'dc:a9:04': 'Apple',
  '00:16:6c': 'Samsung', '00:1a:8a': 'Samsung', '34:23:ba': 'Samsung',
  '5c:0a:5b': 'Samsung', '78:1f:db': 'Samsung', 'bc:76:5e': 'Samsung',
  '18:b4:30': 'Google Nest', '3c:5a:b4': 'Google', 'f4:f5:d8': 'Google',
  '44:65:0d': 'Amazon', '68:37:e9': 'Amazon', 'fc:65:de': 'Amazon',
  'ac:63:be': 'Amazon', '00:fc:8b': 'Amazon',
  '00:1a:11': 'Google', 'd8:eb:46': 'Roku', 'b8:3e:59': 'Roku',
  '00:50:56': 'VMware', '00:0c:29': 'VMware', '08:00:27': 'VirtualBox',
  '52:54:00': 'QEMU/KVM', '00:1c:42': 'Parallels',
  '00:1b:21': 'Intel', '00:1e:67': 'Intel', '3c:fd:fe': 'Intel',
  '00:00:0c': 'Cisco', '00:1a:a1': 'Cisco', 'f0:9f:c2': 'Ubiquiti',
  '24:a4:3c': 'Ubiquiti', '78:8a:20': 'Ubiquiti', 'b4:fb:e4': 'Ubiquiti',
  '00:17:88': 'Philips Hue', 'ec:b5:fa': 'Philips Hue',
  'd0:52:a8': 'SmartThings', '00:24:e4': 'Withings',
  'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
  '00:90:a9': 'Western Digital', '00:11:32': 'Synology', '00:1d:0f': 'TP-Link',
  '50:c7:bf': 'TP-Link', 'c4:e9:84': 'TP-Link', '14:cc:20': 'TP-Link',
  '2c:f0:5d': 'Netgear', 'a0:40:a0': 'Netgear', '00:14:6c': 'Netgear',
};

function vendorForMac(mac) {
  if (!mac) return '';
  const prefix = mac.toLowerCase().slice(0, 8);
  return OUI[prefix] || '';
}

module.exports = {
  FIELDS, FIELD_INDEX, fieldArgs, parseLine,
  PORT_SERVICES, serviceName, OUI, vendorForMac,
};
