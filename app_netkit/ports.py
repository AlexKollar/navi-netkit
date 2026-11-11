"""The offline port/service reference for Navi Netkit.

A curated well-known set, frozen into the chip: number, protocol,
service, what it is, and the one-line risk a defender keeps in mind.
No lookup ever leaves the chip — this is a table, not a probe.
"""

# port: (protocol, service, aliases, what-it-is + risk note)
PORTS = {
    20: ("tcp", "FTP (data)", ("ftp-data",),
         "FTP's separate data channel. Watch: FTP is cleartext — "
         "credentials and files cross readable by anyone on the path."),
    21: ("tcp", "FTP (control)", ("ftp",),
         "FTP sign-in and commands. Watch: cleartext passwords and a "
         "classic brute-force target; prefer SFTP (which rides SSH)."),
    22: ("tcp", "SSH", ("ssh", "secure shell"),
         "Encrypted remote shell, file transfer (SFTP/SCP) and "
         "tunnels. Watch: the internet's most-probed door — key auth "
         "and no root login are the baseline."),
    23: ("tcp", "Telnet", ("telnet",),
         "The pre-SSH remote shell. Watch: everything is cleartext, "
         "passwords included — finding 23 open is a finding, full stop."),
    25: ("tcp", "SMTP", ("smtp", "mail"),
         "Mail relay between servers. Watch: an open relay is a spam "
         "cannon; submission belongs on 587 with auth and TLS."),
    53: ("udp/tcp", "DNS", ("dns", "domain"),
         "Name resolution — UDP for queries, TCP for zone transfers "
         "and big answers. Watch: open resolvers get borrowed for "
         "amplification attacks; zone transfers leak the whole map."),
    67: ("udp", "DHCP (server)", ("dhcp", "bootps"),
         "Hands out addresses to clients broadcasting on 68. Watch: a "
         "rogue DHCP server hands out a rogue gateway — the quiet "
         "way to become the man in the middle."),
    68: ("udp", "DHCP (client)", ("dhcp", "bootpc"),
         "The client's side of DHCP. A machine listening here is "
         "asking the network who it is — it trusts the first answer."),
    69: ("udp", "TFTP", ("tftp",),
         "Trivial file transfer, no authentication at all. Watch: "
         "boot images and device configs move here; anyone can ask, "
         "anyone can read."),
    80: ("tcp", "HTTP", ("http", "www", "web"),
         "The web, unencrypted. Watch: anything typed into an http "
         "page crosses readable — the fix is 443 with a redirect."),
    88: ("tcp/udp", "Kerberos", ("kerberos",),
         "Domain authentication tickets. Watch: the domain's front "
         "door — ticket attacks (Kerberoasting) start by asking "
         "this service politely."),
    110: ("tcp", "POP3", ("pop3",),
         "Mail retrieval, download-and-(usually)-delete. Watch: "
         "cleartext passwords on the base port; 995 is the TLS form."),
    111: ("tcp/udp", "RPCbind", ("rpcbind", "portmapper", "sunrpc"),
         "Maps RPC programs to their ports. Watch: it enumerates "
         "services for whoever asks — a recon gift; keep it off "
         "untrusted networks."),
    123: ("udp", "NTP", ("ntp", "time"),
         "Network time sync. Watch: logs, certs and Kerberos all "
         "trust the clock — poison time and evidence goes wobbly."),
    135: ("tcp", "Microsoft RPC", ("rpc", "msrpc", "epmap"),
         "Windows RPC endpoint mapper. Watch: a long exploit history "
         "(this family carried Blaster) — never expose it to the "
         "internet."),
    139: ("tcp", "NetBIOS Session", ("netbios", "netbios-ssn"),
         "Legacy Windows file sharing over NetBIOS. Watch: a "
         "compatibility fossil that widens the SMB attack surface."),
    143: ("tcp", "IMAP", ("imap",),
         "Mail retrieval that keeps mail on the server. Watch: "
         "cleartext logins on the base port; 993 is the TLS form."),
    161: ("udp", "SNMP", ("snmp",),
         "Device management and monitoring queries. Watch: v1/v2c "
         "'community strings' are cleartext passwords, and the "
         "default 'public' still shows up in the wild."),
    162: ("udp", "SNMP Trap", ("snmptrap", "snmp-trap"),
         "Where devices send their alarms. Watch: unauthenticated "
         "UDP — forged traps can manufacture an incident that never "
         "happened."),
    389: ("tcp/udp", "LDAP", ("ldap", "directory"),
         "Directory lookups — the domain's phone book. Watch: "
         "anonymous binds and cleartext simple binds leak "
         "credentials and the org chart alike."),
    443: ("tcp", "HTTPS", ("https",),
         "HTTP over TLS — the encrypted web. Watch: the service is "
         "fine; the risk lives in expired certs, weak ciphers and "
         "the app behind it."),
    445: ("tcp", "SMB", ("smb", "microsoft-ds", "cifs"),
         "Windows file and printer sharing, modern form. Watch: "
         "EternalBlue made this the most infamous port on earth — "
         "patch it, segment it, never internet-face it."),
    464: ("tcp/udp", "Kerberos Password", ("kpasswd", "kerberos-password"),
         "Domain password changes. Small service, crown-jewel "
         "neighbourhood: it only exists beside a domain controller."),
    500: ("udp", "IKE", ("ike", "isakmp", "ipsec"),
         "IPsec VPN key exchange. Watch: aggressive-mode IKE can "
         "leak a hash of the pre-shared key to anyone who asks."),
    514: ("udp", "Syslog", ("syslog",),
         "Remote logging, fire-and-forget UDP. Watch: unauthenticated "
         "— forged log lines are trivial, so a log server must not "
         "trust a line just because it arrived."),
    515: ("tcp", "LPD", ("lpd", "printer"),
         "The old Unix print queue protocol. Watch: printers are "
         "computers with a paper tray — LPD has been a pivot point "
         "in real intrusions."),
    631: ("tcp", "IPP / CUPS", ("ipp", "cups", "printing"),
         "Modern network printing. Watch: same lesson as 515 — print "
         "services are network services and get CVEs like everything "
         "else."),
    993: ("tcp", "IMAPS", ("imaps", "imap-ssl"),
         "IMAP over TLS — the form 143 should be used in. Watch: "
         "check the cert, not just the port number."),
    995: ("tcp", "POP3S", ("pop3s", "pop3-ssl"),
         "POP3 over TLS — the form 110 should be used in."),
    1080: ("tcp", "SOCKS Proxy", ("socks", "socks5"),
         "A generic proxy door. Watch: an open SOCKS proxy lets "
         "strangers wear your network's address — a pivot and an "
         "abuse magnet."),
    1433: ("tcp", "Microsoft SQL Server", ("mssql", "ms-sql", "sqlserver"),
         "Microsoft's database. Watch: databases should never be "
         "internet-facing; Slammer owned this port in 2003 and it is "
         "still scanned hourly."),
    1521: ("tcp", "Oracle Database", ("oracle", "oracle-db", "sqlnet"),
         "Oracle's listener. Watch: the listener brokers the whole "
         "database — it belongs deep inside the network, not at an "
         "edge."),
    1723: ("tcp", "PPTP", ("pptp", "vpn"),
         "An old VPN protocol. Watch: PPTP's crypto is broken in "
         "practice — its presence means a legacy tunnel that should "
         "be replaced, not trusted."),
    2049: ("tcp/udp", "NFS", ("nfs",),
         "Unix network file shares. Watch: NFS trusts client "
         "machines and UIDs, not users — a writable export can be a "
         "straight line to root."),
    3306: ("tcp", "MySQL", ("mysql", "mariadb"),
         "MySQL/MariaDB. Watch: like every database port — app "
         "servers should be its only callers, ever."),
    3389: ("tcp", "RDP", ("rdp", "remote desktop", "terminal services"),
         "Windows Remote Desktop. Watch: BlueKeep's home and a "
         "ransomware favourite — put it behind a VPN or gateway, "
         "never naked on the internet."),
    5060: ("tcp/udp", "SIP", ("sip", "voip"),
         "VoIP call setup. Watch: SIP endpoints get scanned for "
         "toll fraud — an open PBX can call the world on your bill."),
    5432: ("tcp", "PostgreSQL", ("postgres", "postgresql", "pgsql"),
         "PostgreSQL. Watch: the database rule again — its callers "
         "should be a short, known list."),
    5900: ("tcp", "VNC", ("vnc", "rfb"),
         "Frame-buffer remote desktop. Watch: VNC auth is famously "
         "thin (historically an 8-character password cap) — tunnel "
         "it or lose the machine politely."),
    5985: ("tcp", "WinRM (HTTP)", ("winrm", "wsman"),
         "Windows remote management, PowerShell remoting's door. "
         "Watch: an admin channel by design — on HTTP it should "
         "stay on trusted networks; 5986 is the TLS form."),
    5986: ("tcp", "WinRM (HTTPS)", ("winrm-https", "wsman-https"),
         "WinRM over TLS — the form 5985 should be used in across "
         "anything untrusted."),
    8080: ("tcp", "HTTP (alternate)", ("http-alt", "http-proxy", "alt-http"),
         "The web's side door: dev servers, proxies, admin panels "
         "and appliances live here. Watch: forgotten dev panels on "
         "8080 are a field-day — inventory them."),
    8443: ("tcp", "HTTPS (alternate)", ("https-alt", "alt-https"),
         "TLS web services off the standard port — appliance "
         "consoles especially. Watch: same as 8080, plus a cert "
         "nobody renews because nobody remembers the panel exists."),
}


def _name_index():
    index = {}
    for number, (proto, service, aliases, note) in PORTS.items():
        names = [service.lower(), service.split(" (")[0].lower()]
        names.extend(a.lower() for a in aliases)
        for name in names:
            index.setdefault(name, [])
            if number not in index[name]:
                index[name].append(number)
    return index


_NAME_INDEX = _name_index()


def lookup(query):
    """Resolve a port number or a service name to a list of
    (number, protocol, service, note) rows. Raises ValueError in
    plain words when the offline table has no answer."""
    q = (query or "").strip().lower()
    if not q:
        raise ValueError("give a port number or a service name — "
                         "ports 443, ports ssh")
    if q.isdigit():
        number = int(q)
        if number in PORTS:
            proto, service, _aliases, note = PORTS[number]
            return [(number, proto, service, note)]
        raise ValueError(
            "port %d is not in my offline table — the table covers "
            "the well-known set a course teaches; a port missing "
            "here is not an unused port, just an unlisted one."
            % number)
    hits = _NAME_INDEX.get(q)
    if hits:
        rows = []
        for number in sorted(hits):
            proto, service, _aliases, note = PORTS[number]
            rows.append((number, proto, service, note))
        return rows
    raise ValueError(
        "%r is not a service name in my offline table — try the "
        "port number, or one of: ssh, https, dns, smb, rdp, ldap, "
        "kerberos, mysql." % query)
