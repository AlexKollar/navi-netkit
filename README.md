# Navi Netkit

Networking fundamentals in an Apex chip, built for a cybersecurity
student walking into class with their own arsenal. Subnet and CIDR
math (the exam classics), an offline port/service reference, IP
classification, and MAC parsing — every answer carries the *why*,
and the defender's angle where there is one. The edge isn't the
tool; it's understanding arriving faster than the lecture.

This chip is **pure computation and fully offline**. It never opens a
socket, never asks DNS, never touches the network at all. Nothing it
does can probe a host — it answers questions about numbers you hand
it. It rides in the standard multi-file shape (`root.py` +
`app_netkit/`), forged into one `.png` cartridge whose picture *is*
the install.

## Using it

In Apex chat, or anywhere the chip runs:

```
netkit                          list the commands
netkit <command> -h             one command's help
netkit subnet 192.168.1.10/24  subnet facts
netkit subnet 192.168.1.10 255.255.255.0
netkit cidr 192.168.1.1 192.168.1.200
netkit ports 443                (or: netkit ports ssh)
netkit ports                    lists the whole table
netkit mac AA:BB:CC:11:22:33
netkit ip 192.168.1.10
netkit --test                   self-test against known vectors
```

Worked examples:

```
$ netkit subnet 192.168.1.10/24
Subnet for 192.168.1.0/24
  Network:    192.168.1.0
  Broadcast:  192.168.1.255
  Netmask:    255.255.255.0
  Wildcard:   0.0.0.255
  Addresses:  256 total, 254 usable
  Usable:     192.168.1.1 - 192.168.1.254
  Class:      C
  ...

$ netkit cidr 192.168.1.1 192.168.1.200
Smallest single CIDR covering 192.168.1.1 - 192.168.1.200:
  192.168.1.0/24
```

## The commands

| Command | What it does |
| --- | --- |
| `subnet` | Network, broadcast, netmask, wildcard, total and usable hosts, the usable range, address class, and private/loopback/link-local flags. Also takes a dotted netmask as a second argument. Edge cases are honest: a /31 is two usable hosts (RFC 3021 point-to-point), a /32 is a single host route, IPv6 has no broadcast. |
| `cidr` | The smallest *single* CIDR block covering two addresses, with how much of the block it wastes. The exact fit usually takes several smaller blocks — that's summarization, and the output says so. |
| `ports` | The well-known port/service reference: number, protocol, service, what it is, and the one-line risk note. 43 ports frozen into the chip (20–8443, the exam set). A port number or a service name works (`ports 443`, `ports ssh`). A port missing from the table is *unlisted*, not unused — the chip says so. |
| `mac` | A MAC in any written form (colon, hyphen, dot, bare): all four canonical forms, the OUI prefix, and the two flag bits in the first octet — unicast/multicast (I/G) and global/local (U/L). **No vendor lookup**, on purpose: the OUI database is far too big to ride offline honestly, and a partial one would teach guesses as facts. |
| `ip` | What is this IP: version, historical class, scope — private (RFC 1918), loopback, link-local, CGNAT (100.64.0.0/10), documentation (TEST-NET), multicast, reserved, or public — and the integer, hex and binary forms. |

## Standard library only

Python's `ipaddress` module does the math; the port table and the
MAC rules are frozen into the chip. Nothing to install, nothing to
break, nothing to probe. The `chip-requirements.txt` carries
comments only.

## Install it in Apex

1. Open the **Chips** tab, then **Navi User Repo (NUR)**.
2. **Search NUR** — every public repo tagged `navi-chips` is listed.
3. **Install** — Apex downloads every Python file in the repo at the
   latest release, keeping folder paths, and forges them into a chip:
   `root.py` is the entry, the `app_netkit/` package rides beside
   it, and the runner's package mode makes its imports resolve
   exactly as authored.

## Files

- `root.py` — the chip entry (`run(args)`); small on purpose.
- `app_netkit/core.py` — dispatch, output formatting, `--test`.
- `app_netkit/netmath.py` — subnet, covering-CIDR and IP logic.
- `app_netkit/ports.py` — the frozen offline port table.
- `app_netkit/mac.py` — MAC parsing and the flag bits.
- `navi-chip.json` — the `navi-chip/1` manifest.
- `navi-netkit.png` — the forged cartridge (once forged): the whole
  file set rides inside the picture.

## License

MIT — see `LICENSE`. Copyright (c) SaintsSec.
