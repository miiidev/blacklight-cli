import pytest

from blacklight.guardrails import is_private, verify_targets


@pytest.mark.parametrize(
    "target,expected",
    [
        ("192.168.1.5", True),
        ("192.168.1.0/24", True),
        ("192.168.0.0/16", True),
        ("10.0.0.1", True),
        ("10.0.0.0/8", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("172.16.0.0/12", True),
        ("127.0.0.1", True),
        ("127.0.0.0/8", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("192.169.0.1", False),
        ("172.32.0.1", False),
        ("192.168.0.0/15", False),
        ("not-an-ip", False),
    ],
)
def test_is_private(target, expected):
    assert is_private(target) is expected


def test_verify_targets_blocks_public_without_permission():
    verdict = verify_targets(["192.168.1.5", "8.8.8.8"], permission_granted=False)
    assert verdict.allowed == ["192.168.1.5"]
    assert verdict.needs_confirmation == []
    assert verdict.blocked == ["8.8.8.8"]


def test_verify_targets_requires_confirmation_with_permission():
    verdict = verify_targets(["8.8.8.8"], permission_granted=True)
    assert verdict.allowed == []
    assert verdict.needs_confirmation == ["8.8.8.8"]
    assert verdict.blocked == []


def test_verify_targets_rejects_garbage():
    verdict = verify_targets(["garbage"], permission_granted=True)
    assert verdict.blocked == ["garbage"]
