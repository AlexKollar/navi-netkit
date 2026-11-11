"""Address math for Navi Netkit: subnet facts, the smallest covering
CIDR, and IP classification — all pure computation on Python's
ipaddress module. Nothing here touches a network.

The functions return plain dicts; core.py owns all the printing, so
the self-test can check the math directly instead of parsing text.
"""

import ipaddress

# RFC 1918 private space, checked explicitly. (ipaddress's own
# is_private flag also covers documentation and other special ranges
# in newer Pythons, which would mislabel a TEST-NET address as
# "private" — a student deserves the precise word.)
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_DOC_V4 = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
]
_DOC_V6 = [ipaddress.ip_network("2001:db8::/32")]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK = ipaddress.ip_network("198.18.0.0/15")


def _in(addr, nets):
    return any(addr in n for n in nets)


def address_class(addr):
    """The historical IPv4 class (A–E) from the first octet, or None
    for IPv6 — classes are a v4 teaching artifact, kept because the
    exams still ask."""
    if addr.version != 4:
        return None
    first = int(addr) >> 24
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (reserved/experimental)"


def is_rfc1918(addr):
    return addr.version == 4 and _in(addr, _RFC1918)


def scope_of(addr):
    """One precise scope label for an address, most specific first.
    Returns (label, explainer)."""
    if addr.is_unspecified:
        return ("unspecified",
                "the 'no address' value — a host uses it before it has one.")
    if addr.version == 4 and int(addr) == 0xFFFFFFFF:
        return ("limited broadcast",
                "255.255.255.255 reaches every host on the local link "
                "and is never forwarded by routers.")
    if addr.is_loopback:
        return ("loopback",
                "traffic to this address never leaves the host — it is "
                "the machine talking to itself.")
    if is_rfc1918(addr):
        return ("private (RFC 1918)",
                "routable inside a private network, never on the public "
                "internet — a NAT gateway translates it at the edge.")
    if addr.version == 4 and addr in _CGNAT:
        return ("shared address space (CGNAT, RFC 6598)",
                "100.64.0.0/10 is carrier-grade NAT space: private-like, "
                "but it belongs to the ISP's NAT, not to your LAN.")
    if addr.is_link_local:
        return ("link-local",
                "self-assigned when no address is configured (IPv4 "
                "169.254.0.0/16, IPv6 fe80::/10); works on one link only "
                "and is never routed.")
    if addr.version == 4 and _in(addr, _DOC_V4) or \
            addr.version == 6 and _in(addr, _DOC_V6):
        return ("documentation (TEST-NET)",
                "reserved for books and examples — it looks public but "
                "must never be assigned to a real host.")
    if addr.version == 4 and addr in _BENCHMARK:
        return ("benchmarking (RFC 2544)",
                "198.18.0.0/15 is reserved for lab benchmarking tests.")
    if addr.is_multicast:
        return ("multicast",
                "one sender, many receivers — a group address, never a "
                "host's own address.")
    if addr.is_reserved:
        return ("reserved",
                "set aside by the IETF for future or special use.")
    return ("public (global)",
            "a globally routable address on the public internet.")


def parse_address(text):
    """Parse one IP address or raise ValueError in plain words."""
    try:
        return ipaddress.ip_address((text or "").strip())
    except ValueError:
        raise ValueError("%r is not an IP address I can read — "
                         "try a form like 192.168.1.10" % text)


def subnet_info(ip_text, mask_text=None):
    """Facts about the subnet an address belongs to.

    ip_text may carry its own prefix ("192.168.1.10/24"); mask_text is
    the second form's dotted netmask or prefix ("255.255.255.0" or
    "24"). Host bits in the address are kept — the network is worked
    out from them, the way the exam question is phrased.
    """
    text = (ip_text or "").strip()
    if "/" in text:
        if mask_text is not None:
            raise ValueError("give the mask once — either in the "
                             "address (192.168.1.10/24) or as a second "
                             "value, not both.")
        addr_text, _, mask_text = text.partition("/")
        addr = parse_address(addr_text)
        mask = mask_text.strip()
    else:
        addr = parse_address(text)
        mask = mask_text
    if mask is None or mask == "":
        raise ValueError("a subnet needs its mask — try "
                         "subnet 192.168.1.10/24 or "
                         "subnet 192.168.1.10 255.255.255.0")
    try:
        net = ipaddress.ip_network("%s/%s" % (addr, mask), strict=False)
    except ValueError as exc:
        raise ValueError("that mask does not work for this address: %s"
                         % exc)
    if net.version != addr.version:
        raise ValueError("the mask and the address disagree on IP version.")
    total = net.num_addresses
    info = {
        "ip": addr,
        "network": net,
        "prefixlen": net.prefixlen,
        "netmask": net.netmask,
        "total": total,
        "class": address_class(addr),
        "private": is_rfc1918(addr),
        "loopback": bool(addr.is_loopback),
        "link_local": bool(addr.is_link_local),
        "scope": scope_of(addr)[0],
    }
    if net.version == 4:
        info["wildcard"] = net.hostmask
        info["broadcast"] = net.broadcast_address
        if net.prefixlen == 32:
            info["usable"] = 1
            info["first"] = net.network_address
            info["last"] = net.network_address
            info["note"] = ("a /32 is a host route — the 'subnet' is "
                            "exactly this one address.")
        elif net.prefixlen == 31:
            info["usable"] = 2
            info["first"] = net.network_address
            info["last"] = net.broadcast_address
            info["note"] = ("a /31 is a point-to-point link (RFC 3021): "
                            "both addresses are usable — there is no "
                            "network/broadcast pair to reserve.")
        else:
            info["usable"] = total - 2
            info["first"] = net.network_address + 1
            info["last"] = net.broadcast_address - 1
            info["note"] = ("the network address names the subnet and "
                            "the broadcast reaches every host in it — "
                            "neither is a host's address, which is why "
                            "usable = total - 2.")
    else:
        info["wildcard"] = None
        info["broadcast"] = None
        info["usable"] = total
        info["first"] = net.network_address
        info["last"] = net.network_address + (total - 1)
        info["note"] = ("IPv6 has no broadcast — multicast and "
                        "anycast do that job — so every address in "
                        "the prefix is an address a host can hold.")
    return info


def covering_cidr(a_text, b_text):
    """The smallest SINGLE CIDR block that contains both addresses,
    plus how much room it wastes versus the exact range."""
    a = parse_address(a_text)
    b = parse_address(b_text)
    if a.version != b.version:
        raise ValueError("both addresses must be the same IP version "
                         "to share a CIDR block.")
    lo, hi = (a, b) if int(a) <= int(b) else (b, a)
    # The covering prefix is the run of leading bits the two share:
    # walk down from the full length until their networks agree.
    bits = 32 if a.version == 4 else 128
    prefix = bits
    while prefix > 0:
        cand = ipaddress.ip_network("%s/%d" % (lo, prefix), strict=False)
        if hi in cand:
            break
        prefix -= 1
    net = ipaddress.ip_network("%s/%d" % (lo, prefix), strict=False)
    range_count = int(hi) - int(lo) + 1
    return {
        "lo": lo,
        "hi": hi,
        "network": net,
        "range_count": range_count,
        "block_count": net.num_addresses,
        "waste": net.num_addresses - range_count,
    }


def ip_info(text):
    """A parsed address with its class, scope and numeric forms."""
    addr = parse_address(text)
    label, explainer = scope_of(addr)
    info = {
        "ip": addr,
        "version": addr.version,
        "class": address_class(addr),
        "scope": label,
        "explainer": explainer,
        "integer": int(addr),
    }
    if addr.version == 4:
        info["binary"] = ".".join(
            format(int(octet), "08b") for octet in addr.packed)
        info["hex"] = "0x%08X" % int(addr)
    else:
        info["binary"] = ":".join(
            format(int(group, 16), "016b")
            for group in addr.exploded.split(":"))
        info["hex"] = "0x%032X" % int(addr)
        info["expanded"] = addr.exploded
    return info
