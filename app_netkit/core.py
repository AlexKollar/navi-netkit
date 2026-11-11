"""Navi Netkit command core: dispatch, output formatting, and the
--test self-test table.

Grammar:
    netkit                        list the commands
    netkit <command> -h           one command's help
    netkit subnet <ip>/<cidr>     subnet facts (or: subnet <ip> <mask>)
    netkit cidr <ip> <ip>         smallest CIDR covering both
    netkit ports <n|name>         offline port/service reference
    netkit mac <address>          MAC forms, OUI and flag bits
    netkit ip <address>           what is this IP
    netkit --test                 self-test against known vectors

Design law of the series: explain, don't just execute — every answer
carries the why, and the defender's angle where there is one. Pure
computation only: nothing in this chip touches a network.
"""

try:
    from . import mac as mac_mod
    from . import netmath, ports as ports_mod
except ImportError:  # imported outside the package (should not happen)
    from app_netkit import mac as mac_mod
    from app_netkit import netmath, ports as ports_mod

VERSION = "1.0.0"
USAGE = ('usage: netkit <command> [args]  |  netkit --test\n'
         "commands: subnet, cidr, ports, mac, ip")

_HELP = {
    "subnet": (
        "subnet — the facts of the subnet an address lives in.\n"
        "use: netkit subnet 192.168.1.10/24\n"
        "     netkit subnet 192.168.1.10 255.255.255.0\n"
        "Network, broadcast, netmask, wildcard, total and usable "
        "hosts, the usable range, class and scope flags."),
    "cidr": (
        "cidr — the smallest single CIDR block covering two "
        "addresses (the other exam classic).\n"
        "use: netkit cidr 192.168.1.1 192.168.1.200"),
    "ports": (
        "ports — the offline well-known port/service reference.\n"
        "use: netkit ports 443      (or: netkit ports ssh)\n"
        "     netkit ports          lists the whole table.\n"
        "Frozen into the chip: a reference table, never a probe."),
    "mac": (
        "mac — parse a MAC address in any written form.\n"
        "use: netkit mac AA:BB:CC:11:22:33\n"
        "Canonical forms, the OUI prefix, and the unicast/multicast "
        "and global/local bits. No vendor lookup — see the output."),
    "ip": (
        "ip — what is this IP address.\n"
        "use: netkit ip 192.168.1.10\n"
        "Version, class, scope (private, loopback, CGNAT, "
        "documentation, public...), and the integer/binary forms."),
}


def print_list():
    print("Navi Netkit %s — networking fundamentals in a chip." % VERSION)
    print(USAGE)
    print("")
    print("  subnet   subnet facts: network, broadcast, usable hosts")
    print("  cidr     smallest CIDR block covering two addresses")
    print("  ports    offline port/service reference (443, ssh, ...)")
    print("  mac      MAC forms, OUI prefix, flag bits explained")
    print("  ip       what is this IP: class, scope, numeric forms")
    print("")
    print("netkit <command> -h shows one command's help. Everything "
          "is pure computation — this chip never touches a network.")


# ---------------------------------------------------------------- subnet

def _yn(flag):
    return "yes" if flag else "no"


def cmd_subnet(argv):
    if len(argv) == 1:
        info = netmath.subnet_info(argv[0])
    elif len(argv) == 2:
        info = netmath.subnet_info(argv[0], argv[1])
    else:
        raise ValueError("subnet takes an address with its mask: "
                         "netkit subnet 192.168.1.10/24")
    net = info["network"]
    print("Subnet for %s" % net)
    print("  Address:    %s" % info["ip"])
    print("  Network:    %s" % net.network_address)
    if net.version == 4:
        print("  Broadcast:  %s" % info["broadcast"])
        print("  Netmask:    %s" % info["netmask"])
        print("  Wildcard:   %s" % info["wildcard"])
    else:
        print("  Broadcast:  none — IPv6 does not broadcast")
        print("  Netmask:    /%d (IPv6 masks are written as prefixes)"
              % info["prefixlen"])
    print("  Addresses:  %s total, %s usable"
          % (format(info["total"], ","), format(info["usable"], ",")))
    print("  Usable:     %s - %s" % (info["first"], info["last"]))
    if info["class"]:
        print("  Class:      %s" % info["class"])
    print("  Scope:      %s" % info["scope"])
    print("  Flags:      private %s · loopback %s · link-local %s"
          % (_yn(info["private"]), _yn(info["loopback"]),
             _yn(info["link_local"])))
    print("Why it matters: %s" % info["note"])
    print("Defender's angle: subnetting is segmentation — smaller "
          "subnets mean smaller blast radii, and a broadcast domain "
          "is the room a noisy or compromised host can shout into.")
    return 0


# ------------------------------------------------------------------ cidr

def cmd_cidr(argv):
    if len(argv) != 2:
        raise ValueError("cidr takes two addresses: "
                         "netkit cidr 192.168.1.1 192.168.1.200")
    res = netmath.covering_cidr(argv[0], argv[1])
    net = res["network"]
    print("Smallest single CIDR covering %s - %s:" % (res["lo"], res["hi"]))
    print("  %s" % net)
    print("  Block:      %s - %s (%s addresses)"
          % (net.network_address,
             net.network_address + (res["block_count"] - 1),
             format(res["block_count"], ",")))
    print("  Your range: %s addresses" % format(res["range_count"], ","))
    if res["waste"]:
        print("  Waste:      %s addresses of the block sit outside "
              "your range" % format(res["waste"], ","))
        print("Why it matters: one CIDR must start on its own "
              "boundary, so a single block almost always over-covers. "
              "An exact fit usually takes several smaller blocks — "
              "that splitting is called summarization, and ACLs and "
              "route tables are written in these blocks either way.")
    else:
        print("Why it matters: this range IS a CIDR block exactly — "
              "it starts on its boundary and fills the block, the "
              "clean case route tables dream about.")
    return 0


# ----------------------------------------------------------------- ports

def cmd_ports(argv):
    if not argv:
        print("The offline table — %d well-known ports. "
              "netkit ports <n|name> for the notes on one."
              % len(ports_mod.PORTS))
        print("")
        for number in sorted(ports_mod.PORTS):
            proto, service, _a, _n = ports_mod.PORTS[number]
            print("  %-6s %-10s %s" % (number, proto, service))
        return 0
    if len(argv) != 1:
        raise ValueError("ports takes one port number or service "
                         "name: netkit ports 443")
    for number, proto, service, note in ports_mod.lookup(argv[0]):
        print("%d/%s — %s" % (number, proto, service))
        print("  %s" % note)
    print("Defender's angle: a port is only a door number — what "
          "matters is what answers behind it, whether it should, and "
          "who can reach it. This table is reference, never a scan.")
    return 0


# ------------------------------------------------------------------- mac

def cmd_mac(argv):
    if len(argv) != 1:
        raise ValueError("mac takes one address: "
                         "netkit mac AA:BB:CC:11:22:33")
    m = mac_mod.parse_mac(argv[0])
    print("MAC %s" % m["colon"])
    print("  Colon:   %s" % m["colon"])
    print("  Hyphen:  %s" % m["hyphen"])
    print("  Dot:     %s" % m["dot"])
    print("  Bare:    %s" % m["bare"])
    print("  OUI:     %s (first 24 bits — the vendor's block, in "
          "principle)" % m["oui"])
    print("  Device:  %s (last 24 bits — the card's own number "
          "inside the block)" % m["device_part"])
    if m["broadcast"]:
        print("  Type:    broadcast — FF:FF:FF:FF:FF:FF reaches every "
              "card on the link.")
    elif m["zero"]:
        print("  Type:    the zero address — a placeholder, not a "
              "real card.")
    else:
        print("  Type:    %s (I/G bit %d)"
              % ("multicast — a group address, many receivers"
                 if m["multicast"] else
                 "unicast — one card, one receiver",
                 1 if m["multicast"] else 0))
        print("  Admin:   %s (U/L bit %d)"
              % ("locally administered — made up on the spot (a VM, "
                 "a phone's randomized Wi-Fi address), NOT burned "
                 "in by a vendor"
                 if m["locally_administered"] else
                 "globally unique — assigned from the vendor's OUI "
                 "block",
                 1 if m["locally_administered"] else 0))
    print("Why it matters: this chip names no vendor — the OUI "
          "database is far too big to ride offline honestly, and a "
          "partial one would teach guesses as facts. The bits above "
          "are facts. Defender's angle: a locally-administered bit "
          "on a 'server' is a question worth asking.")
    return 0


# -------------------------------------------------------------------- ip

def cmd_ip(argv):
    if len(argv) != 1:
        raise ValueError("ip takes one address: netkit ip 192.168.1.10")
    info = netmath.ip_info(argv[0])
    addr = info["ip"]
    print("%s — IPv%d" % (addr, info["version"]))
    if info["class"]:
        print("  Class:    %s" % info["class"])
    print("  Scope:    %s — %s" % (info["scope"], info["explainer"]))
    print("  Integer:  %d" % info["integer"])
    print("  Hex:      %s" % info["hex"])
    if info["version"] == 6:
        print("  Expanded: %s" % info["expanded"])
    print("  Binary:   %s" % info["binary"])
    print("Why it matters: the scope decides who may route it — a "
          "'public-looking' address that is really documentation or "
          "CGNAT space has fooled real configurations, and spotting "
          "it starts here.")
    return 0


_COMMANDS = {
    "subnet": cmd_subnet,
    "cidr": cmd_cidr,
    "ports": cmd_ports,
    "mac": cmd_mac,
    "ip": cmd_ip,
}


def _run(argv):
    if not argv:
        print_list()
        return 0
    head = argv[0]
    if head == "--test":
        return self_test()
    if head in ("--help", "-h", "help"):
        print_list()
        return 0
    name = head.lower()
    fn = _COMMANDS.get(name)
    if fn is None:
        print("unknown command %r — run netkit with no arguments "
              "for the list." % head)
        return 2
    rest = argv[1:]
    if any(t in ("-h", "--help") for t in rest) or \
            (not rest and name != "ports"):
        print(_HELP[name])
        return 0
    return fn(rest)


def run_command(argv):
    """Entry for root.py. Prints everything; never tracebacks on
    bad input — a chip answers honestly or not at all."""
    try:
        return _run(list(argv))
    except ValueError as exc:
        print("error: " + str(exc))
        return 1
    except Exception as exc:  # a chip in a sandbox stays polite
        print("error: " + str(exc))
        return 1


# -------------------------------------------------------------- self-test

def self_test():
    nm = netmath
    checks = [
        ("subnet /24 network",
         lambda: str(nm.subnet_info("192.168.1.10/24")["network"]
                     .network_address) == "192.168.1.0"),
        ("subnet /24 broadcast",
         lambda: str(nm.subnet_info("192.168.1.10/24")["broadcast"])
         == "192.168.1.255"),
        ("subnet /24 usable 254",
         lambda: nm.subnet_info("192.168.1.10/24")["usable"] == 254),
        ("subnet /24 first/last usable",
         lambda: str(nm.subnet_info("192.168.1.10/24")["first"])
         == "192.168.1.1"
         and str(nm.subnet_info("192.168.1.10/24")["last"])
         == "192.168.1.254"),
        ("subnet /24 netmask + wildcard",
         lambda: str(nm.subnet_info("192.168.1.10/24")["netmask"])
         == "255.255.255.0"
         and str(nm.subnet_info("192.168.1.10/24")["wildcard"])
         == "0.0.0.255"),
        ("subnet /24 class C + private",
         lambda: nm.subnet_info("192.168.1.10/24")["class"] == "C"
         and nm.subnet_info("192.168.1.10/24")["private"] is True),
        ("subnet netmask form equals /24",
         lambda: str(nm.subnet_info("192.168.1.10", "255.255.255.0")
                     ["network"]) == "192.168.1.0/24"),
        ("subnet /8 facts",
         lambda: str(nm.subnet_info("10.0.0.1/8")["broadcast"])
         == "10.255.255.255"
         and nm.subnet_info("10.0.0.1/8")["usable"] == 16777214
         and nm.subnet_info("10.0.0.1/8")["class"] == "A"),
        ("subnet /31 both usable (RFC 3021)",
         lambda: nm.subnet_info("192.168.1.10/31")["usable"] == 2
         and str(nm.subnet_info("192.168.1.10/31")["first"])
         == "192.168.1.10"
         and str(nm.subnet_info("192.168.1.10/31")["last"])
         == "192.168.1.11"),
        ("subnet /32 single host",
         lambda: nm.subnet_info("192.168.1.10/32")["usable"] == 1
         and nm.subnet_info("192.168.1.10/32")["total"] == 1),
        ("subnet host-bits address kept",
         lambda: str(nm.subnet_info("192.168.1.10/24")["ip"])
         == "192.168.1.10"),
        ("subnet bad mask refused",
         lambda: _raises(lambda: nm.subnet_info("192.168.1.10",
                                                "255.255.0.255"))),
        ("cidr 192.168.1.1-200 is /24",
         lambda: str(nm.covering_cidr("192.168.1.1", "192.168.1.200")
                     ["network"]) == "192.168.1.0/24"),
        ("cidr waste counted",
         lambda: nm.covering_cidr("192.168.1.1", "192.168.1.200")
         ["waste"] == 56
         and nm.covering_cidr("192.168.1.1", "192.168.1.200")
         ["range_count"] == 200),
        ("cidr exact block wastes 0",
         lambda: nm.covering_cidr("192.168.1.0", "192.168.1.255")
         ["waste"] == 0),
        ("cidr order does not matter",
         lambda: str(nm.covering_cidr("192.168.1.200", "192.168.1.1")
                     ["network"]) == "192.168.1.0/24"),
        ("cidr same address twice is /32",
         lambda: str(nm.covering_cidr("10.1.2.3", "10.1.2.3")
                     ["network"]) == "10.1.2.3/32"),
        ("cidr 10.0.0.1-10.0.1.1 is /23",
         lambda: str(nm.covering_cidr("10.0.0.1", "10.0.1.1")
                     ["network"]) == "10.0.0.0/23"),
        ("ports 443 is HTTPS",
         lambda: ports_mod.lookup("443")[0][2] == "HTTPS"),
        ("ports ssh is 22",
         lambda: ports_mod.lookup("ssh")[0][0] == 22),
        ("ports dns is 53 udp/tcp",
         lambda: ports_mod.lookup("dns")[0][0] == 53
         and "udp" in ports_mod.lookup("dns")[0][1]),
        ("ports smb is 445",
         lambda: ports_mod.lookup("smb")[0][0] == 445),
        ("ports unknown number refused",
         lambda: _raises(lambda: ports_mod.lookup("59999"))),
        ("ports unknown name refused",
         lambda: _raises(lambda: ports_mod.lookup("nosuchservice"))),
        ("ports table covers the exam set",
         lambda: all(p in ports_mod.PORTS for p in (
             20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111,
             123, 135, 139, 143, 161, 162, 389, 443, 445, 464, 500,
             514, 515, 631, 993, 995, 1080, 1433, 1521, 1723, 2049,
             3306, 3389, 5060, 5432, 5900, 5985, 5986, 8080, 8443))),
        ("mac colon form parses",
         lambda: mac_mod.parse_mac("AA:BB:CC:11:22:33")["colon"]
         == "AA:BB:CC:11:22:33"),
        ("mac dot form equals colon form",
         lambda: mac_mod.parse_mac("aabb.cc11.2233")["colon"]
         == "AA:BB:CC:11:22:33"),
        ("mac bare + hyphen forms agree",
         lambda: mac_mod.parse_mac("AABBCC112233")["hyphen"]
         == "AA-BB-CC-11-22-33"),
        ("mac OUI is first three octets",
         lambda: mac_mod.parse_mac("AA:BB:CC:11:22:33")["oui"]
         == "AA:BB:CC"),
        ("mac AA is unicast + locally administered",
         lambda: mac_mod.parse_mac("AA:BB:CC:11:22:33")["multicast"]
         is False
         and mac_mod.parse_mac("AA:BB:CC:11:22:33")
         ["locally_administered"] is True),
        ("mac 01 is multicast + global",
         lambda: mac_mod.parse_mac("01:00:5E:00:00:FB")["multicast"]
         is True
         and mac_mod.parse_mac("01:00:5E:00:00:FB")
         ["locally_administered"] is False),
        ("mac broadcast recognised",
         lambda: mac_mod.parse_mac("FF:FF:FF:FF:FF:FF")["broadcast"]
         is True),
        ("mac bad digit refused",
         lambda: _raises(lambda: mac_mod.parse_mac("GG:BB:CC:11:22:33"))),
        ("mac short form refused",
         lambda: _raises(lambda: mac_mod.parse_mac("AA:BB:CC:11:22"))),
        ("ip private scope",
         lambda: nm.ip_info("192.168.1.10")["scope"]
         == "private (RFC 1918)"),
        ("ip public scope",
         lambda: nm.ip_info("8.8.8.8")["scope"] == "public (global)"),
        ("ip loopback scope",
         lambda: nm.ip_info("127.0.0.1")["scope"] == "loopback"),
        ("ip link-local scope",
         lambda: nm.ip_info("169.254.1.1")["scope"] == "link-local"),
        ("ip CGNAT scope",
         lambda: nm.ip_info("100.64.0.1")["scope"]
         .startswith("shared address space")),
        ("ip documentation scope",
         lambda: nm.ip_info("192.0.2.1")["scope"]
         .startswith("documentation")),
        ("ip integer form",
         lambda: nm.ip_info("192.168.1.10")["integer"] == 3232235786),
        ("ip binary form",
         lambda: nm.ip_info("192.168.1.10")["binary"]
         == "11000000.10101000.00000001.00001010"),
        ("ip bad address refused",
         lambda: _raises(lambda: nm.ip_info("999.1.1.1"))),
        ("ip v6 loopback",
         lambda: nm.ip_info("::1")["version"] == 6
         and nm.ip_info("::1")["scope"] == "loopback"),
    ]
    passed = 0
    for label, fn in checks:
        try:
            ok = bool(fn())
            detail = ""
        except Exception as exc:
            ok = False
            detail = ": " + str(exc)
        print("%s %s%s" % ("PASS" if ok else "FAIL", label, detail))
        if ok:
            passed += 1
    print("self-test: %d/%d passed" % (passed, len(checks)))
    return 0 if passed == len(checks) else 1


def _raises(fn):
    try:
        fn()
    except ValueError:
        return True
    return False
