"""Navi Netkit — networking fundamentals that ride inside an Apex chip.

Standard library only, pure computation: subnet/CIDR math, an offline
port/service reference, IP classification and MAC parsing. Nothing in
this package touches a network — no sockets, no DNS, no HTTP — so the
chip works fully offline and never probes anything.
"""

__version__ = "1.0.0"
