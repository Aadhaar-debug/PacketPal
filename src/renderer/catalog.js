'use strict';
/* Browser-side lookup tables + device identification.
   Turns raw MAC / hostname / user-agent / DHCP clues into a friendly
   "what is this thing" label, so users see "John's iPhone" instead of a MAC. */
(function (global) {
  const PORT_SERVICES = {
    20: 'FTP data', 21: 'FTP (file transfer)', 22: 'SSH (secure shell)',
    23: 'Telnet (INSECURE remote login)', 25: 'SMTP (email sending)',
    53: 'DNS (domain lookups)', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP (web, unencrypted)', 110: 'POP3 (email, often plaintext)',
    111: 'RPC', 123: 'NTP (clock sync)', 135: 'MS RPC', 137: 'NetBIOS name',
    138: 'NetBIOS datagram', 139: 'NetBIOS / SMB', 143: 'IMAP (email)',
    161: 'SNMP', 389: 'LDAP', 443: 'HTTPS (secure web)', 445: 'SMB (file sharing)',
    465: 'SMTPS (secure email)', 514: 'Syslog', 548: 'AFP (Apple file sharing)',
    587: 'SMTP (email submission)', 631: 'IPP (printing)', 636: 'LDAPS',
    853: 'DNS over TLS', 993: 'IMAPS (secure email)', 995: 'POP3S (secure email)',
    1080: 'SOCKS proxy', 1433: 'MS SQL', 1521: 'Oracle DB', 1883: 'MQTT (IoT)',
    3306: 'MySQL database', 3389: 'RDP (remote desktop)', 5000: 'UPnP / dev server',
    5060: 'SIP (VoIP calls)', 5228: 'Google services', 5353: 'mDNS (Bonjour/local discovery)',
    5432: 'PostgreSQL', 5900: 'VNC (screen sharing)', 6379: 'Redis',
    7000: 'AirPlay', 8080: 'HTTP alt (web)', 8443: 'HTTPS alt', 8883: 'Secure MQTT (IoT)',
    9100: 'Printer (raw)', 27017: 'MongoDB', 32400: 'Plex media server',
    3478: 'STUN (video calls)', 443: 'HTTPS (secure web)', 1900: 'SSDP (device discovery)',
  };
  function serviceName(port) {
    const n = parseInt(port, 10);
    if (PORT_SERVICES[n]) return PORT_SERVICES[n];
    if (!n && n !== 0) return '';
    if (n >= 49152) return 'Dynamic / private port';
    return 'Port ' + n;
  }

  // MAC OUI (first 3 octets) -> vendor. Partial but covers common consumer gear.
  const OUI = {
    // Apple
    '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0a:27': 'Apple', '00:0a:95': 'Apple',
    '00:1b:63': 'Apple', '00:1e:c2': 'Apple', '00:1f:f3': 'Apple', '00:25:00': 'Apple',
    '00:26:bb': 'Apple', '04:0c:ce': 'Apple', '04:15:52': 'Apple', '0c:3e:9f': 'Apple',
    '14:10:9f': 'Apple', '18:af:61': 'Apple', '1c:ab:a7': 'Apple', '28:cf:e9': 'Apple',
    '2c:b4:3a': 'Apple', '34:36:3b': 'Apple', '38:71:de': 'Apple', '3c:07:54': 'Apple',
    '40:a6:d9': 'Apple', '44:d8:84': 'Apple', '48:60:bc': 'Apple', '4c:57:ca': 'Apple',
    '50:ea:d6': 'Apple', '58:55:ca': 'Apple', '5c:59:48': 'Apple', '60:33:4b': 'Apple',
    '64:b9:e8': 'Apple', '68:ab:bc': 'Apple', '6c:40:08': 'Apple', '70:cd:60': 'Apple',
    '74:e2:f5': 'Apple', '78:4f:43': 'Apple', '7c:6d:62': 'Apple', '80:e6:50': 'Apple',
    '84:38:35': 'Apple', '88:63:df': 'Apple', '8c:85:90': 'Apple', '90:72:40': 'Apple',
    '94:e9:6a': 'Apple', '98:01:a7': 'Apple', '9c:04:eb': 'Apple', 'a4:5e:60': 'Apple',
    'a8:66:7f': 'Apple', 'ac:bc:32': 'Apple', 'b0:34:95': 'Apple', 'b8:e8:56': 'Apple',
    'bc:52:b7': 'Apple', 'c0:84:7a': 'Apple', 'c8:1e:e7': 'Apple', 'cc:08:e0': 'Apple',
    'd0:81:7a': 'Apple', 'd4:9a:20': 'Apple', 'dc:a9:04': 'Apple', 'e0:ac:cb': 'Apple',
    'e4:98:d6': 'Apple', 'e8:80:2e': 'Apple', 'f0:18:98': 'Apple', 'f4:1b:a1': 'Apple',
    'f8:1e:df': 'Apple', 'fc:25:3f': 'Apple',
    // Samsung
    '00:16:6c': 'Samsung', '00:1a:8a': 'Samsung', '00:21:19': 'Samsung', '08:37:3d': 'Samsung',
    '10:d5:42': 'Samsung', '1c:62:b8': 'Samsung', '20:13:e0': 'Samsung', '28:39:5e': 'Samsung',
    '34:23:ba': 'Samsung', '38:aa:3c': 'Samsung', '5c:0a:5b': 'Samsung', '78:1f:db': 'Samsung',
    '8c:77:12': 'Samsung', 'a0:21:95': 'Samsung', 'bc:76:5e': 'Samsung', 'c8:19:f7': 'Samsung',
    'e8:50:8b': 'Samsung', 'fc:a1:3e': 'Samsung',
    // Google / Nest
    '18:b4:30': 'Google Nest', '1c:f2:9a': 'Google', '20:df:b9': 'Google', '3c:5a:b4': 'Google',
    '54:60:09': 'Google', '64:16:66': 'Google Nest', '94:eb:2c': 'Google', 'd8:6c:63': 'Google',
    'f4:f5:d8': 'Google', 'f8:8f:ca': 'Google Nest',
    // Amazon
    '0c:47:c9': 'Amazon', '34:d2:70': 'Amazon', '38:f7:3d': 'Amazon', '44:65:0d': 'Amazon',
    '50:dc:e7': 'Amazon', '68:37:e9': 'Amazon', '68:54:fd': 'Amazon', '74:c2:46': 'Amazon',
    'ac:63:be': 'Amazon', 'f0:27:2d': 'Amazon', 'fc:65:de': 'Amazon', '00:fc:8b': 'Amazon',
    // Roku
    'd8:eb:46': 'Roku', 'b8:3e:59': 'Roku', 'dc:3a:5e': 'Roku', 'cc:6d:a0': 'Roku',
    'ac:3a:7a': 'Roku', '88:de:a9': 'Roku',
    // Microsoft (Xbox / Surface)
    '00:50:f2': 'Microsoft', '00:12:5a': 'Microsoft', '7c:1e:52': 'Microsoft', '98:5f:d3': 'Microsoft',
    'c0:33:5e': 'Microsoft', '3c:83:75': 'Microsoft',
    // Sony (PlayStation)
    '00:04:1f': 'Sony', '00:13:15': 'Sony', '00:19:c5': 'Sony', 'a8:e3:ee': 'Sony',
    'bc:60:a7': 'Sony', 'fc:0f:e6': 'Sony',
    // Nintendo
    '00:09:bf': 'Nintendo', '00:1a:e9': 'Nintendo', '58:bd:a3': 'Nintendo', '98:b6:e9': 'Nintendo',
    'e8:4e:ce': 'Nintendo',
    // Virtualization
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
    '00:1c:42': 'Parallels', '00:16:3e': 'Xen',
    // Intel
    '00:1b:21': 'Intel', '00:1e:67': 'Intel', '3c:fd:fe': 'Intel', '7c:7a:91': 'Intel',
    '8c:16:45': 'Intel', 'a0:a8:cd': 'Intel', 'e4:a7:a0': 'Intel',
    // Networking gear
    '00:00:0c': 'Cisco', '00:1a:a1': 'Cisco', 'f0:9f:c2': 'Ubiquiti', '24:a4:3c': 'Ubiquiti',
    '78:8a:20': 'Ubiquiti', 'b4:fb:e4': 'Ubiquiti', 'fc:ec:da': 'Ubiquiti',
    '00:1d:0f': 'TP-Link', '50:c7:bf': 'TP-Link', 'c4:e9:84': 'TP-Link', '14:cc:20': 'TP-Link',
    '2c:f0:5d': 'Netgear', 'a0:40:a0': 'Netgear', '00:14:6c': 'Netgear', '9c:3d:cf': 'Netgear',
    '00:18:0a': 'Meraki', '00:24:a5': 'Buffalo', '00:1d:7e': 'Belkin', 'ec:1a:59': 'Belkin',
    '00:90:4c': 'Epson', '58:b0:d4': ' zte',
    // IoT / smart home
    '00:17:88': 'Philips Hue', 'ec:b5:fa': 'Philips Hue', '00:0b:57': 'Philips Hue',
    'd0:52:a8': 'SmartThings', '24:fd:5b': 'SmartThings', '00:24:e4': 'Withings',
    '18:b7:9e': 'Wyze', '2c:aa:8e': 'Wyze', '7c:78:b2': 'Wyze',
    '54:ef:44': 'Lumi/Aqara', '50:ec:50': 'Sonos', '00:0e:58': 'Sonos', '94:9f:3e': 'Sonos',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
    '28:cd:c1': 'Raspberry Pi',
    // NAS / storage
    '00:90:a9': 'Western Digital', '00:11:32': 'Synology', '00:1d:0f': 'TP-Link',
    '00:08:9b': 'QNAP', '24:5e:be': 'QNAP',
    // Printers
    '00:1b:a9': 'Brother', '30:05:5c': 'Brother', '9c:93:4e': 'Xerox', '00:1e:8f': 'Canon',
    '2c:9e:fc': 'Canon', '08:00:37': 'Epson', '44:d2:44': 'Epson',
    // LG / Vizio / TCL (TVs)
    '00:1c:62': 'LG', '2c:54:cf': 'LG', 'cc:2d:8c': 'LG', '00:19:9d': 'Vizio',
    'c4:9d:ed': 'Microsoft', '8c:79:67': 'TCL', 'b0:a7:37': 'Roku',
    // OnePlus / Xiaomi / Huawei / OPPO
    '94:65:2d': 'OnePlus', '64:a2:f9': 'OnePlus', '64:09:80': 'Xiaomi', '28:6c:07': 'Xiaomi',
    '3c:bd:3e': 'Xiaomi', '00:9a:cd': 'Huawei', '48:3c:0c': 'Huawei', '20:a6:80': 'Huawei',
  };
  function vendorForMac(mac) {
    if (!mac) return '';
    // locally-administered / random MAC (privacy address) -> unknown vendor
    const first = parseInt(mac.slice(0, 2), 16);
    if (!isNaN(first) && (first & 0x02)) return 'Private address';
    return OUI[mac.toLowerCase().slice(0, 8)] || '';
  }

  // Device-type rules checked against hostname + user-agent + DHCP vendor class.
  const RULES = [
    [/iphone/i, 'iPhone', '📱'],
    [/\bipad\b/i, 'iPad', '📱'],
    [/\bipod\b/i, 'iPod', '🎵'],
    [/macbook|\bmbp\b|\bmba\b/i, 'MacBook', '💻'],
    [/imac/i, 'iMac', '🖥️'],
    [/mac[- ]?mini/i, 'Mac mini', '🖥️'],
    [/mac[- ]?pro|macos|mac os x/i, 'Mac', '🖥️'],
    [/apple[- ]?tv|appletv/i, 'Apple TV', '📺'],
    [/apple[- ]?watch|watch\d/i, 'Apple Watch', '⌚'],
    [/homepod/i, 'HomePod', '🔊'],
    [/airpods/i, 'AirPods', '🎧'],
    [/pixel/i, 'Google Pixel', '📱'],
    [/nexus/i, 'Nexus', '📱'],
    [/galaxy|sm-[a-z]\d|samsung.*phone/i, 'Samsung Galaxy', '📱'],
    [/oneplus/i, 'OnePlus', '📱'],
    [/redmi|xiaomi|\bmi[- ]?\d/i, 'Xiaomi', '📱'],
    [/huawei|honor/i, 'Huawei', '📱'],
    [/\boppo\b|\bvivo\b/i, 'Phone', '📱'],
    [/android/i, 'Android device', '📱'],
    [/chromebook|\bcros\b/i, 'Chromebook', '💻'],
    [/windows[- ]?phone/i, 'Windows Phone', '📱'],
    [/windows|msft 5|microsoft|surface/i, 'Windows PC', '🖥️'],
    [/ubuntu|debian|fedora|archlinux|\blinux\b/i, 'Linux PC', '🐧'],
    [/\becho\b|alexa|amazon.*echo/i, 'Amazon Echo', '🔊'],
    [/fire[- ]?tv|firetv|aftt|afts|aftm/i, 'Fire TV', '📺'],
    [/kindle/i, 'Kindle', '📖'],
    [/\broku\b/i, 'Roku', '📺'],
    [/chromecast/i, 'Chromecast', '📺'],
    [/nest[- ]?hub|nest[- ]?mini|google[- ]?home/i, 'Google Home', '🔊'],
    [/\bnest\b/i, 'Google Nest', '🏠'],
    [/playstation|\bps[345]\b|\bps4\b|\bps5\b/i, 'PlayStation', '🎮'],
    [/\bxbox\b/i, 'Xbox', '🎮'],
    [/nintendo|switch/i, 'Nintendo Switch', '🎮'],
    [/roomba|irobot/i, 'Robot vacuum', '🤖'],
    [/\bhue\b|lifx|smart[- ]?bulb|smartbulb/i, 'Smart light', '💡'],
    [/\bring\b|doorbell/i, 'Smart doorbell', '🔔'],
    [/wyze|\bcam\b|camera|ipcam/i, 'Camera', '📷'],
    [/thermostat|ecobee/i, 'Thermostat', '🌡️'],
    [/sonos|\bspeaker\b/i, 'Speaker', '🔊'],
    [/raspberry|raspberrypi/i, 'Raspberry Pi', '🍓'],
    [/synology|diskstation|\bqnap\b|\bnas\b|freenas/i, 'NAS (storage)', '🗄️'],
    [/printer|laserjet|officejet|\bepson\b|\bbrother\b|\bcanon\b/i, 'Printer', '🖨️'],
    [/bravia|aquos|\bvizio\b|\btcl\b|smart[- ]?tv|\bwebos\b|\btizen\b/i, 'Smart TV', '📺'],
    [/router|gateway|openwrt|dd-wrt|\bunifi\b|\beero\b|orbi/i, 'Router / Wi-Fi', '📡'],
  ];

  // Trim marketing suffixes off a vendor string: "Apple, Inc." -> "Apple".
  function cleanVendor(v) {
    if (!v) return '';
    let s = v.replace(/[.,]+$/, '').trim();
    if (/^(icann|iana|ieee)\b/i.test(s)) return ''; // not a device maker
    s = s.replace(/,?\s*(inc|inc\.|llc|ltd|co\.?|corp(oration)?|technologies?|technology|gmbh|company|electronics|international)\.?$/i, '').trim();
    s = s.replace(/,?\s*(inc|llc|ltd|corp|co)\.?$/i, '').trim();
    return s || v.replace(/[.,]+$/, '');
  }

  // Pick the richest name we can for a device.
  // d: { vendor, hostname, userAgent, vendorClass, mac, local, appleHint, privateMac }
  function identifyDevice(d) {
    const clues = [d.hostname, d.userAgent, d.vendorClass].filter(Boolean).join('  ');
    let type = null, icon = null;
    for (const [re, name, ic] of RULES) {
      if (re.test(clues) || (d.vendor && re.test(d.vendor))) { type = name; icon = ic; break; }
    }
    // Clean the announced hostname (strip .local, NetBIOS suffixes)
    const nice = (d.hostname || '').replace(/\.local\.?$/i, '').replace(/<[0-9a-fx]+>$/i, '').trim();
    const vend = cleanVendor(d.vendor);

    let name, confidence;
    if (nice && type) { name = nice; confidence = 'high'; }
    else if (nice) { name = nice; confidence = 'high'; }
    else if (type) { name = vend && !new RegExp(vend, 'i').test(type) ? `${type} (${vend})` : type; confidence = 'high'; }
    else if (vend) { name = `${vend} device`; confidence = 'medium'; icon = icon || vendorIcon(d.vendor); }
    else if (d.appleHint) { name = 'Apple device'; type = 'Apple'; icon = '📱'; confidence = 'medium'; }
    else { name = d.local ? 'Unidentified device' : 'Internet server'; confidence = 'low'; }

    if (d.appleHint && /apple/i.test(vend) && !type) { icon = '📱'; }
    if (!icon) icon = type ? icon : (d.local ? '🔌' : '☁️');
    return { name, type: type || vend || '', icon, confidence, vendor: vend };
  }

  function vendorIcon(v) {
    if (/apple/i.test(v)) return '';
    if (/samsung|google|huawei|xiaomi|oneplus/i.test(v)) return '📱';
    if (/roku|amazon|lg|vizio|tcl/i.test(v)) return '📺';
    if (/hue|sonos|withings|wyze|smartthings/i.test(v)) return '🏠';
    if (/raspberry/i.test(v)) return '🍓';
    if (/cisco|ubiquiti|tp-link|netgear|meraki|belkin/i.test(v)) return '📡';
    if (/synology|qnap|western digital/i.test(v)) return '🗄️';
    if (/epson|canon|brother|xerox/i.test(v)) return '🖨️';
    return '🔌';
  }

  global.Catalog = { PORT_SERVICES, serviceName, OUI, vendorForMac, identifyDevice };
})(window);
