"""Tests for the bundled role-preset registry."""
from __future__ import annotations

from ironmesh.roles import ROLES, get_role_prompt, list_roles


def test_assistant_exists_and_nonempty():
    p = get_role_prompt("assistant")
    assert p is not None
    assert len(p) > 20


def test_unknown_role_returns_none():
    assert get_role_prompt("bogus") is None


def test_list_roles_is_sorted():
    assert list_roles() == sorted(list_roles())


def test_all_roles_have_nonempty_prompts():
    for name, prompt in ROLES.items():
        assert isinstance(prompt, str), f"{name} prompt must be str"
        assert len(prompt) > 20, f"{name} prompt suspiciously short"


def test_role_names_are_valid_capability_strings():
    # role:<name> will be advertised as a capability; names should be
    # the kind of string a capability glob can match cleanly.
    import re
    pat = re.compile(r"^[a-z0-9][a-z0-9-]*$")
    for name in ROLES:
        assert pat.match(name), f"{name!r} not a clean capability token"


def test_has_expected_roles():
    # Minimum set of roles we rely on in documentation and the deployed mesh.
    for expected in ("assistant", "security-analyst", "network-engineer"):
        assert expected in ROLES
