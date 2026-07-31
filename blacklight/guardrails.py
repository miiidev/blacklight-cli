"""Authorization guardrails: default-deny scanning of non-private targets."""

import ipaddress
from dataclasses import dataclass

PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


@dataclass
class Verdict:
    """Result of validating scan targets.

    allowed: safe to scan immediately (fully private).
    needs_confirmation: public targets the user claimed permission for;
        the CLI must still prompt before scanning.
    blocked: rejected (public without permission, or unparseable).
    """

    allowed: list[str]
    needs_confirmation: list[str]
    blocked: list[str]

    @property
    def has_public_targets(self) -> bool:
        return bool(self.needs_confirmation)


def is_private(target: str) -> bool:
    """True if the whole target (host or CIDR) falls inside private ranges.

    Uses subnet containment, so a CIDR that includes any public address
    (e.g. 192.168.0.0/15) is correctly treated as not private.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return any(net.subnet_of(private) for private in PRIVATE_NETWORKS)


def verify_targets(targets: list[str], permission_granted: bool) -> Verdict:
    """Classify each target into allowed / needs_confirmation / blocked."""
    allowed: list[str] = []
    needs_confirmation: list[str] = []
    blocked: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            blocked.append(target)
            continue
        if is_private(target):
            allowed.append(target)
        elif permission_granted:
            needs_confirmation.append(target)
        else:
            blocked.append(target)
    return Verdict(allowed=allowed, needs_confirmation=needs_confirmation, blocked=blocked)
