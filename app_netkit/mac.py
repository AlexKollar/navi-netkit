"""MAC address parsing for Navi Netkit: the four written forms, the
OUI prefix, and the two flag bits in the first octet.

Deliberately NO vendor table: a real OUI database is far too big to
ride in a chip honestly, and a partial one would teach guesses as
facts. The bits, though, are facts — the first octet says whether
the address is unicast or multicast, and whether it was assigned by
a vendor or made up locally.
"""

_HEX = set("0123456789abcdefABCDEF")


def _digits(text):
    s = (text or "").strip()
    if not s:
        raise ValueError("give a MAC address — mac AA:BB:CC:11:22:33")
    if ":" in s:
        parts = s.split(":")
        if len(parts) != 6 or any(len(p) != 2 for p in parts):
            raise ValueError("%r is not in colon form — six groups of "
                             "two hex digits, like AA:BB:CC:11:22:33" % text)
        raw = "".join(parts)
    elif "-" in s:
        parts = s.split("-")
        if len(parts) != 6 or any(len(p) != 2 for p in parts):
            raise ValueError("%r is not in hyphen form — six groups of "
                             "two hex digits, like AA-BB-CC-11-22-33" % text)
        raw = "".join(parts)
    elif "." in s:
        parts = s.split(".")
        if len(parts) != 3 or any(len(p) != 4 for p in parts):
            raise ValueError("%r is not in dot form — three groups of "
                             "four hex digits, like AABB.CC11.2233" % text)
        raw = "".join(parts)
    else:
        raw = s
        if len(raw) != 12:
            raise ValueError("%r has %d characters — a bare MAC is 12 "
                             "hex digits (48 bits), like AABBCC112233"
                             % (text, len(raw)))
    if any(c not in _HEX for c in raw):
        raise ValueError("%r carries a character that is not a hex "
                         "digit — MAC addresses are hex, 0-9 and A-F"
                         % text)
    return [int(raw[i:i + 2], 16) for i in range(0, 12, 2)]


def parse_mac(text):
    """Parse any of the four written forms into facts about the
    address. Raises ValueError in plain words on a bad address."""
    octets = _digits(text)
    bare = "".join("%02X" % o for o in octets)
    first = octets[0]
    multicast = bool(first & 0x01)
    local = bool(first & 0x02)
    return {
        "octets": octets,
        "colon": ":".join("%02X" % o for o in octets),
        "hyphen": "-".join("%02X" % o for o in octets),
        "dot": ".".join(bare[i:i + 4] for i in range(0, 12, 4)),
        "bare": bare,
        "oui": ":".join("%02X" % o for o in octets[:3]),
        "device_part": ":".join("%02X" % o for o in octets[3:]),
        "multicast": multicast,
        "locally_administered": local,
        "broadcast": all(o == 0xFF for o in octets),
        "zero": all(o == 0x00 for o in octets),
    }
