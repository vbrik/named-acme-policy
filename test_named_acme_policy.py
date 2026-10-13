"""Unit tests for named-acme-policy.py.

The script's hyphenated filename can't be `import`ed, so `_load_module` below
loads it through a custom loader that also skips the bytecode cache.
"""

import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

MODULE_PATH = Path(__file__).parent / "named-acme-policy.py"


class _UncachedLoader(importlib.machinery.SourceFileLoader):
    """SourceFileLoader that always compiles from source.

    The inherited `get_code` consults `__pycache__`, and CPython accepts a
    cached `.pyc` whenever the source's size and whole-second mtime match the
    values in its header. An edit preserving byte count that lands in the same
    second as the previous run satisfies both, so the suite would silently
    execute bytecode for code no longer on disk.
    """

    def get_code(self, fullname):
        # Delegate the compile so this keeps CPython's dont_inherit=True --
        # otherwise a __future__ import in this test module would change how
        # the module under test is compiled.
        return self.source_to_code(self.get_data(self.path), self.path)


def _load_module(path=MODULE_PATH):
    """Load a hyphen-named script as a module, ignoring any bytecode cache."""
    name = path.stem.replace("-", "_")
    loader = _UncachedLoader(name, str(path))
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    assert spec and spec.loader
    # module_from_spec sets __name__, so the `if __name__ == "__main__"` guard
    # still keeps main() from running at import time.
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nap = _load_module()


def build_request(
    signer="certbot",
    rr_name="_acme-challenge.example.com",
    src_addr="10.0.0.1",
    rr_type="TXT",
):
    """Pack a request message in the on-wire format `unpack_req_msg` expects."""
    parts = [
        signer.encode(),
        rr_name.encode(),
        src_addr.encode(),
        rr_type.encode(),
        b"certbot/1/1",
        b"",
    ]
    return b"\x00" * 8 + b"\x00".join(parts)


class TestUnpackReqMsg:
    def test_docstring_example(self):
        data = (
            b"\x00\x00\x00\x01\x00\x00\x00bcertbot\x00_acme-challenge.bookstack."
            b"icecube.wisc.edu\x00144.92.100.35\x00TXT\x00certbot/165/7089\x00"
            b"\x00\x00\x00"
        )
        assert nap.unpack_req_msg(data) == {
            "signer": "certbot",
            "rr_name": "_acme-challenge.bookstack.icecube.wisc.edu",
            "src_addr": "144.92.100.35",
            "rr_type": "TXT",
        }

    def test_round_trips_constructed_message(self):
        data = build_request(
            signer="my-signer",
            rr_name="_acme-challenge.host.example.org",
            src_addr="192.0.2.5",
            rr_type="TXT",
        )
        assert nap.unpack_req_msg(data) == {
            "signer": "my-signer",
            "rr_name": "_acme-challenge.host.example.org",
            "src_addr": "192.0.2.5",
            "rr_type": "TXT",
        }

    def test_too_few_fields_raises(self):
        # Missing the trailing rr_type/tag fields entirely.
        data = b"\x00" * 8 + b"certbot\x00_acme-challenge.example.com\x00"
        with pytest.raises(ValueError):
            nap.unpack_req_msg(data)


class FakeResolver:
    """Stubs the `resolver` argument for both the A and PTR lookups.

    is_valid_acme_update uses this same injected resolver for both queries
    (DETAILED_HELP's "WHY A SEPARATE DNS SERVER": a non-local resolver is
    required to avoid deadlock, since named(8) evaluates this synchronously
    against itself), so a single stub tracking both is enough. Records are
    given as text and returned as real rdata, as dnspython would; also like
    dnspython, an empty answer raises NoAnswer rather than returning [].

    `name_a_records` overrides `a_records` per absolute name, e.g.
    {"host.example.org.": ["10.0.0.1"]}, a value being either records or an
    exception to raise. `on_query(name, rdtype)` runs before each lookup. Copies,
    as made to clip `lifetime`, share `calls` and `lifetimes`, which record each
    lookup and the lifetime it ran with.
    """

    def __init__(
        self,
        a_records=(),
        ptr_records=(),
        raise_on_a=None,
        raise_on_ptr=None,
        name_a_records=None,
        on_query=None,
    ):
        self.a_records = list(a_records)
        self.ptr_records = list(ptr_records)
        self.raise_on_a = raise_on_a
        self.raise_on_ptr = raise_on_ptr
        self.name_a_records = name_a_records or {}
        self.on_query = on_query
        self.lifetime = 0.5
        self.calls = []
        self.lifetimes = []

    def query(self, name, rdtype):
        self.calls.append((name, rdtype))
        self.lifetimes.append(self.lifetime)
        if self.on_query:
            self.on_query(name, rdtype)
        if rdtype == "A" and str(name) in self.name_a_records:
            entry = self.name_a_records[str(name)]
            exc, records = (
                (entry, ()) if isinstance(entry, Exception) else (None, entry)
            )
        elif rdtype == "A":
            exc, records = self.raise_on_a, self.a_records
        elif rdtype == "PTR":
            exc, records = self.raise_on_ptr, self.ptr_records
        else:
            raise AssertionError(f"unexpected rdtype {rdtype!r}")
        if exc is not None:
            raise exc
        if not records:
            raise dns.resolver.NoAnswer()
        return [_rdata(rdtype, r) for r in records]


def _rdata(rdtype, text):
    """Parse `text` into IN-class rdata of `rdtype`, e.g. ("PTR", "example.com.")."""
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), text)


# Each failure with the level it should be logged at: resolver trouble is an
# ERROR, a negative answer a WARNING.
DNS_FAILURES = [
    pytest.param(dns.resolver.NXDOMAIN(), "WARNING", id="NXDOMAIN"),
    pytest.param(dns.resolver.NoAnswer(), "WARNING", id="NoAnswer"),
    pytest.param(dns.exception.Timeout(), "ERROR", id="Timeout"),
    pytest.param(dns.resolver.NoNameservers(), "ERROR", id="NoNameservers"),
]
# What dnspython >= 2.2 raises in production when resolver.lifetime runs out;
# older versions, such as RHEL 8's 1.15, raise plain Timeout and lack the class.
if hasattr(dns.resolver, "LifetimeTimeout"):
    DNS_FAILURES.append(
        pytest.param(
            dns.resolver.LifetimeTimeout(timeout=0.5, errors=[]),
            "ERROR",
            id="LifetimeTimeout",
        )
    )


class TestIsValidAcmeUpdate:
    def test_wrong_subdomain_denied_without_dns_lookup(self):
        msg = {
            "signer": "certbot",
            "rr_name": "not-acme.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert resolver.calls == []

    def test_wrong_rr_type_denied_without_dns_lookup(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "A",
        }
        resolver = FakeResolver()
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert resolver.calls == []

    def test_unconfigured_signer_denied_without_dns_lookup(self):
        msg = {
            "signer": "someone-else",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert resolver.calls == []

    def test_unconfigured_signer_denied_even_with_static_map_hit(self):
        # Signer lookup must precede the static-map shortcut: a static mapping
        # authorizes a source IP for a domain, but only under a configured signer.
        msg = {
            "signer": "someone-else",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        signers = {"certbot": {"10.0.0.1": ["example.com"]}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is False
        assert resolver.calls == []

    def test_static_map_hit_grants_after_existence_check_only(self):
        # The domain's A records needn't include the source address; the
        # lookup only establishes that the domain exists.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"])
        signers = {"certbot": {"10.0.0.1": ["other.example.org", "example.com"]}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is True
        assert [rdtype for _, rdtype in resolver.calls] == ["A"]

    def test_wildcard_static_map_entry_grants_any_existing_domain(self):
        msg = {
            "signer": "k8s-certbot",
            "rr_name": "_acme-challenge.anything.example.net",
            "src_addr": "10.1.2.3",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"])
        signers = {"k8s-certbot": {"10.1.2.3": "*"}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is True
        assert [rdtype for _, rdtype in resolver.calls] == ["A"]

    @pytest.mark.parametrize(
        "allowed", ["*", ["example.com"]], ids=["wildcard", "listed"]
    )
    @pytest.mark.parametrize(("exc", "level"), DNS_FAILURES)
    def test_static_map_hit_denied_unless_domain_exists(
        self, allowed, exc, level, caplog
    ):
        # Existence is checked before the static map is consulted, and
        # resolver trouble fails closed: existence can't be confirmed.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(raise_on_a=exc)
        signers = {"certbot": {"10.0.0.1": allowed}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is False
        assert [rdtype for _, rdtype in resolver.calls] == ["A"]
        (record,) = caplog.records
        assert record.levelname == level
        assert record.message.startswith(
            f"Existence check (A lookup) of example.com failed: {type(exc).__name__}"
        )

    def test_domain_without_a_record_denied_even_by_wildcard(self):
        # E.g. an AAAA-only name: the stub raises NoAnswer for an empty A set.
        msg = {
            "signer": "k8s-certbot",
            "rr_name": "_acme-challenge.v6only.example.net",
            "src_addr": "10.1.2.3",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        signers = {"k8s-certbot": {"10.1.2.3": "*"}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is False

    def test_wildcard_entry_for_other_ip_does_not_grant_unlisted_ip(self):
        # A signer's wildcard grant is scoped to the specific IPs listed for
        # it; a request from an IP that isn't in its map at all still falls
        # through to the normal resolver-based check.
        msg = {
            "signer": "k8s-certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "192.168.1.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"], ptr_records=["other.com."])
        signers = {"k8s-certbot": {"10.1.2.3": "*"}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is False

    def test_malformed_bare_string_map_value_does_not_substring_match(self):
        # A map value must be "*" or a list of domains. A bare domain string
        # (e.g. forgetting the list brackets) must not be treated as a grant
        # via Python's `in` substring containment on the request's domain.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.ample.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"], ptr_records=["other.com."])
        signers = {"certbot": {"10.0.0.1": "example.com"}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is False

    def test_static_map_present_but_no_matching_domain_falls_through_to_dns(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["10.0.0.1"])
        signers = {"certbot": {"10.0.0.1": ["unrelated.example.org"]}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is True

    def test_forward_resolution_match_grants(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["10.0.0.1", "10.0.0.2"])
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is True

    def test_reverse_resolution_match_grants_multihomed_case(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "192.168.1.1",
            "rr_type": "TXT",
        }
        # Forward lookup returns only the public address; source is an
        # internal address whose PTR record points back to the domain.
        resolver = FakeResolver(a_records=["203.0.113.5"], ptr_records=["example.com."])
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is True
        # The PTR lookup must go through the injected resolver, not the
        # module-level dns.resolver.query (see the FakeResolver docstring).
        assert [(str(name), rdtype) for name, rdtype in resolver.calls] == [
            ("example.com.", "A"),
            ("1.1.168.192.in-addr.arpa.", "PTR"),
        ]

    def test_ptr_record_without_trailing_dot_does_not_match(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "192.168.1.1",
            "rr_type": "TXT",
        }
        # Missing the trailing dot that a real PTR RRset would have.
        resolver = FakeResolver(a_records=["203.0.113.5"], ptr_records=["example.com"])
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False

    def test_neither_forward_nor_reverse_match_denies(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "192.168.1.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(
            a_records=["203.0.113.5"], ptr_records=["other-domain.com."]
        )
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False

    def test_ptr_match_ignores_case(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "192.168.1.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"], ptr_records=["Example.COM."])
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is True

    def test_forward_lookup_uses_absolute_name(self):
        # A relative name would let query() append the search domain, which
        # Resolver(configure=False) still derives from the host's FQDN.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["10.0.0.1"])
        nap.is_valid_acme_update(msg, {"certbot": {}}, resolver)
        ((name, _),) = resolver.calls
        assert name.is_absolute()

    @pytest.mark.parametrize(("exc", "level"), DNS_FAILURES)
    def test_forward_lookup_failure_denies_without_ptr_lookup(self, exc, level, caplog):
        # A failed forward lookup ends evaluation and is logged here rather
        # than propagated to main(), whose log line would lack context.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(raise_on_a=exc, ptr_records=["example.com."])
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert [rdtype for _, rdtype in resolver.calls] == ["A"]
        (record,) = caplog.records
        assert record.levelname == level
        assert record.message.startswith(
            f"Existence check (A lookup) of example.com failed: {type(exc).__name__}"
        )

    def test_forward_match_grants_without_ptr_lookup(self):
        # Regression: an unrelated PTR failure (NXDOMAIN for a private address
        # via a public resolver) used to deny requests the forward match
        # already justified, because the PTR lookup ran unconditionally.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(
            a_records=["10.0.0.1"], raise_on_ptr=dns.resolver.NXDOMAIN()
        )
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is True
        assert [rdtype for _, rdtype in resolver.calls] == ["A"]

    @pytest.mark.parametrize(("exc", "level"), DNS_FAILURES)
    def test_ptr_lookup_failure_without_forward_match_denies(self, exc, level, caplog):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "144.92.100.35",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"], raise_on_ptr=exc)
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        (record,) = caplog.records
        assert record.levelname == level
        assert record.message.startswith(
            f"Reverse lookup of 144.92.100.35 failed: {type(exc).__name__}"
        )
        assert "--dns" not in record.message

    @pytest.mark.parametrize(
        "src_addr", ["10.128.108.231", "100.64.1.1", "fd00::1"], ids=str
    )
    def test_non_global_address_ptr_nxdomain_log_points_at_dns_option(
        self, src_addr, caplog
    ):
        # The case that prompted the hint: a public --dns resolver answers
        # NXDOMAIN for a private (or e.g. CGNAT) address's PTR.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": src_addr,
            "rr_type": "TXT",
        }
        resolver = FakeResolver(
            a_records=["203.0.113.5"], raise_on_ptr=dns.resolver.NXDOMAIN()
        )
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert (
            f"Reverse lookup of {src_addr} failed: NXDOMAIN"
            " (non-global address: does --dns serve its reverse zone?)" in caplog.text
        )

    @pytest.mark.parametrize(
        "exc",
        [
            dns.exception.Timeout(),
            dns.resolver.NoAnswer(),
            dns.resolver.NoNameservers(),
        ],
        ids=lambda e: type(e).__name__,
    )
    def test_non_global_address_other_ptr_failure_log_has_no_hint(self, exc, caplog):
        # The hint explains NXDOMAIN; for other failures it would mislead.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"], raise_on_ptr=exc)
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert f"Reverse lookup of 10.0.0.1 failed: {type(exc).__name__}" in caplog.text
        assert "--dns" not in caplog.text

    def test_mismatch_log_shows_what_dns_returned(self, caplog):
        caplog.set_level("INFO")
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "192.168.1.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"], ptr_records=["other.com."])
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False
        assert (
            "Source check failed: example.com -> ['203.0.113.5'],"
            " 192.168.1.1 -> ['other.com.']" in caplog.text
        )

    def test_malformed_rr_name_without_dot_raises(self):
        # split(".", 1) yields a single element; unpacking into
        # (subdomain, domain) raises ValueError.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        with pytest.raises(ValueError):
            nap.is_valid_acme_update(msg, {"certbot": {}}, resolver)

    def test_non_ip_src_addr_raises_on_reverse_lookup(self):
        # dns.reversename.from_address requires a parseable IP address;
        # a garbage src_addr (e.g. from a malformed request) propagates
        # a SyntaxError from dnspython rather than returning False.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "not-an-ip",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(a_records=["203.0.113.5"])
        with pytest.raises(Exception):  # noqa: B017 -- dnspython's own error type
            nap.is_valid_acme_update(msg, {"certbot": {}}, resolver)


def _name(text):
    return dns.name.from_text(text)


def _acme_msg(src_addr="10.0.0.1", domain="example.com", signer="certbot"):
    return {
        "signer": signer,
        "rr_name": f"_acme-challenge.{domain}",
        "src_addr": src_addr,
        "rr_type": "TXT",
    }


class FakeClock:
    """Stands in for the `time` module, whose monotonic() only moves on advance()."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestNameKeys:
    """Host-name keys in signer maps, as `load_signer_maps` produces them."""

    HOST = "host.example.org."

    def _looked_up(self, resolver):
        return [str(name) for name, _ in resolver.calls]

    def test_grants_when_name_resolves_to_source(self, caplog):
        caplog.set_level("INFO")
        resolver = FakeResolver(
            a_records=["203.0.113.5"], name_a_records={self.HOST: ["10.0.0.1"]}
        )
        signers = {"certbot": {_name(self.HOST): ["example.com"]}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert self._looked_up(resolver) == ["example.com.", self.HOST]
        assert f"via static map name {self.HOST} " in caplog.text

    @pytest.mark.parametrize(
        ("src_addr", "expected"),
        [("10.0.0.3", True), ("10.0.0.1", False)],
        ids=["among-them", "not-among-them"],
    )
    def test_source_must_be_among_several_addresses(self, src_addr, expected):
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records={self.HOST: ["10.0.0.2", "10.0.0.3"]},
        )
        signers = {"certbot": {_name(self.HOST): ["example.com"]}}
        msg = _acme_msg(src_addr=src_addr)
        assert nap.is_valid_acme_update(msg, signers, resolver) is expected

    def test_name_is_resolved_afresh_on_every_request(self):
        records = {self.HOST: ["10.0.0.1"]}
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records=records,
        )
        signers = {"certbot": {_name(self.HOST): ["example.com"]}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        records[self.HOST] = ["10.0.0.9"]
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is False
        assert self._looked_up(resolver).count(self.HOST) == 2

    def test_wildcard_value_grants_any_existing_domain(self):
        resolver = FakeResolver(
            a_records=["203.0.113.5"], name_a_records={self.HOST: ["10.0.0.1"]}
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        msg = _acme_msg(domain="anything.example.net")
        assert nap.is_valid_acme_update(msg, signers, resolver) is True

    def test_name_not_looked_up_unless_its_value_covers_the_domain(self):
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records={self.HOST: ["10.0.0.1"]},
        )
        signers = {"certbot": {_name(self.HOST): ["other.example.com"]}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is False
        assert self.HOST not in self._looked_up(resolver)

    def test_name_not_looked_up_when_an_ip_key_grants(self):
        resolver = FakeResolver(
            a_records=["203.0.113.5"], name_a_records={self.HOST: ["10.0.0.1"]}
        )
        signers = {
            "certbot": {"10.0.0.1": ["example.com"], _name(self.HOST): ["example.com"]}
        }
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert self._looked_up(resolver) == ["example.com."]

    def test_name_not_looked_up_when_forward_lookup_grants(self):
        resolver = FakeResolver(
            a_records=["10.0.0.1"], name_a_records={self.HOST: ["10.0.0.1"]}
        )
        signers = {"certbot": {_name(self.HOST): ["example.com"]}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert self._looked_up(resolver) == ["example.com."]

    @pytest.mark.parametrize(("exc", "_level"), DNS_FAILURES)
    def test_lookup_failure_is_an_error_and_falls_through_to_reverse(
        self, exc, _level, caplog
    ):
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["example.com."],
            name_a_records={self.HOST: exc},
        )
        signers = {"certbot": {_name(self.HOST): ["example.com"]}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert [rdtype for _, rdtype in resolver.calls] == ["A", "A", "PTR"]
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1
        assert errors[0].message.startswith(
            f"Signer-map name lookup of {self.HOST} failed: {type(exc).__name__}"
        )

    def test_failed_name_does_not_keep_a_later_one_from_granting(self):
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            name_a_records={
                "bad.example.org.": dns.resolver.NXDOMAIN(),
                self.HOST: ["10.0.0.1"],
            },
        )
        signers = {
            "certbot": {
                _name("bad.example.org."): ["example.com"],
                _name(self.HOST): ["example.com"],
            }
        }
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True

    def test_ipv6_source_skips_name_keys(self):
        # Name keys hold A records only, so looking them up can't help.
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records={self.HOST: ["10.0.0.1"]},
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        msg = _acme_msg(src_addr="2001:db8::5")
        assert nap.is_valid_acme_update(msg, signers, resolver) is False
        assert self.HOST not in self._looked_up(resolver)

    def test_denial_log_shows_what_names_resolved_to(self, caplog):
        caplog.set_level("INFO")
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records={
                self.HOST: ["10.0.0.9"],
                "bad.example.org.": dns.resolver.NXDOMAIN(),
            },
        )
        signers = {"certbot": {_name(self.HOST): "*", _name("bad.example.org."): "*"}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is False
        (line,) = [m for m in caplog.messages if m.startswith("Source check failed")]
        assert f"{self.HOST} -> ['10.0.0.9']" in line
        assert "bad.example.org. -> NXDOMAIN" in line

    def test_names_are_looked_up_in_parallel(self):
        # A sequential loop would block on the slow name, listed first, before
        # reaching the matching one.
        release = threading.Event()

        def on_query(name, rdtype):
            if str(name) == "slow.example.org.":
                release.wait(5)

        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            name_a_records={"slow.example.org.": [], self.HOST: ["10.0.0.1"]},
            on_query=on_query,
        )
        signers = {"certbot": {_name("slow.example.org."): "*", _name(self.HOST): "*"}}
        start = time.monotonic()
        try:
            assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
            assert time.monotonic() - start < 1
        finally:
            release.set()

    def test_name_step_stops_in_time_for_the_reverse_lookup(self, monkeypatch, caplog):
        # With a 0.7 budget and a 0.5 lifetime, names get 0.2 s; the hung one
        # is abandoned and the reverse lookup still grants.
        monkeypatch.setattr(nap, "DECISION_BUDGET", 0.7)
        release = threading.Event()

        def on_query(name, rdtype):
            if str(name) == self.HOST:
                release.wait(5)

        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["example.com."],
            name_a_records={self.HOST: ["10.0.0.9"]},
            on_query=on_query,
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        start = time.monotonic()
        try:
            assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
            assert time.monotonic() - start < 1
        finally:
            release.set()
        assert (
            f"Decision budget exhausted awaiting name lookups: {self.HOST}"
            in caplog.text
        )

    def test_reverse_lookup_keeps_its_full_lifetime_after_names_hang(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(nap, "time", clock)
        monkeypatch.setattr(nap, "DECISION_BUDGET", 1.5)

        def on_query(name, rdtype):
            if str(name) == self.HOST:
                clock.advance(1.0)  # all the time the name step has

        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["example.com."],
            name_a_records={self.HOST: dns.exception.Timeout()},
            on_query=on_query,
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert resolver.lifetimes == pytest.approx([0.5, 0.5, 0.5])

    def test_lookups_are_clipped_to_the_decision_deadline(self, monkeypatch):
        # The existence check uses up 0.8 of the 1.5 budget. The name step, which
        # leaves the reverse lookup a full 0.5 lifetime, gets the 0.2 between.
        clock = FakeClock()
        monkeypatch.setattr(nap, "time", clock)
        monkeypatch.setattr(nap, "DECISION_BUDGET", 1.5)

        def on_query(name, rdtype):
            if str(name) == "example.com.":
                clock.advance(0.8)

        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records={self.HOST: ["10.0.0.9"]},
            on_query=on_query,
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is False
        assert [rdtype for _, rdtype in resolver.calls] == ["A", "A", "PTR"]
        assert resolver.lifetimes == pytest.approx([0.5, 0.2, 0.5])
        assert resolver.lifetime == 0.5

    def test_timeout_of_a_clipped_lookup_blames_the_budget(self, monkeypatch, caplog):
        clock = FakeClock()
        monkeypatch.setattr(nap, "time", clock)
        monkeypatch.setattr(nap, "DECISION_BUDGET", 1.5)

        def on_query(name, rdtype):
            if str(name) == "example.com.":
                clock.advance(0.8)

        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["example.com."],
            name_a_records={self.HOST: dns.exception.Timeout()},
            on_query=on_query,
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert (
            f"Signer-map name lookup of {self.HOST} failed: Timeout: decision budget"
            " exhausted (0.200 s were left)" in caplog.text
        )

    def test_unclipped_timeout_keeps_the_resolver_message(self, caplog):
        exc = dns.exception.Timeout()
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["example.com."],
            name_a_records={self.HOST: exc},
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is True
        assert f"failed: Timeout: {exc}" in caplog.text

    def test_no_lookup_is_started_past_the_deadline(self, monkeypatch, caplog):
        clock = FakeClock()
        monkeypatch.setattr(nap, "time", clock)
        monkeypatch.setattr(nap, "DECISION_BUDGET", 1.5)

        def on_query(name, rdtype):
            clock.advance(1.6)

        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["example.com."],
            name_a_records={self.HOST: ["10.0.0.1"]},
            on_query=on_query,
        )
        signers = {"certbot": {_name(self.HOST): "*"}}
        assert nap.is_valid_acme_update(_acme_msg(), signers, resolver) is False
        assert self._looked_up(resolver) == ["example.com."]

    def test_budget_is_per_decision(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(nap, "time", clock)
        monkeypatch.setattr(nap, "DECISION_BUDGET", 1.5)
        resolver = FakeResolver(
            a_records=["203.0.113.5"],
            ptr_records=["other.example.org."],
            name_a_records={self.HOST: ["10.0.0.9"]},
            on_query=lambda name, rdtype: clock.advance(0.45),
        )
        signers = {"certbot": {_name(self.HOST): ["example.com"]}}
        for _ in range(3):
            nap.is_valid_acme_update(_acme_msg(), signers, resolver)
        assert [rdtype for _, rdtype in resolver.calls] == ["A", "A", "PTR"] * 3


class TestLoadSignerMaps:
    HOSTNAME = "dns1.example.org"

    def _load(self, tmp_path, content, hostname=HOSTNAME):
        path = tmp_path / "maps.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return nap.load_signer_maps(str(path), hostname)

    def test_ip_keys_and_values_are_kept(self, tmp_path):
        content = {
            "certbot": {"10.0.0.1": ["a.example.com"], "2001:db8::1": "*", "::2": []}
        }
        assert self._load(tmp_path, content) == content

    @pytest.mark.parametrize(
        ("key", "normal"),
        [("2001:DB8:0::1", "2001:db8::1"), ("2001:0db8:0000::0001", "2001:db8::1")],
    )
    def test_ip_keys_are_normalized(self, tmp_path, key, normal):
        assert self._load(tmp_path, {"c": {key: "*"}}) == {"c": {normal: "*"}}

    def test_ipv4_mapped_key_matches_the_same_source(self, tmp_path):
        # Python versions disagree on str() of such addresses, so the request's
        # source address must be normalized the same way as the key.
        signers = self._load(tmp_path, {"certbot": {"::ffff:10.0.0.1": "*"}})
        resolver = FakeResolver(a_records=["203.0.113.5"])
        msg = _acme_msg(src_addr="::ffff:10.0.0.1")
        assert nap.is_valid_acme_update(msg, signers, resolver) is True

    def test_two_spellings_of_one_address_are_rejected(self, tmp_path):
        content = {"certbot": {"2001:db8::1": "*", "2001:DB8::1": ["a.example.com"]}}
        with pytest.raises(ValueError, match="both name 2001:db8::1"):
            self._load(tmp_path, content)

    @pytest.mark.parametrize(
        "content",
        [
            '{"certbot": {"10.0.0.1": "*", "10.0.0.1": ["a.example.com"]}}',
            '{"certbot": {"10.0.0.1": "*"}, "certbot": {"10.0.0.2": "*"}}',
        ],
        ids=["source", "signer"],
    )
    def test_duplicate_json_keys_are_rejected(self, tmp_path, content):
        with pytest.raises(ValueError, match="duplicate key"):
            self._load(tmp_path, content)

    @pytest.mark.parametrize(
        "key",
        [
            "10.0.0.0/24",
            "10.0.0.1:53",
            "10.0.0.1 ",
            "_comment",
            "-host.example.org",
            "host-.example.org",
            "host_name.example.org",
            "",
        ],
    )
    def test_non_host_name_key_is_rejected(self, tmp_path, key):
        with pytest.raises(ValueError, match="neither an IP address nor a host name"):
            self._load(tmp_path, {"certbot": {key: "*"}})

    @pytest.mark.parametrize(
        "value", ["example.com", ["a.example.com", 1], 5, None, {"a": 1}, "**"]
    )
    def test_value_other_than_star_or_domain_list_is_rejected(self, tmp_path, value):
        with pytest.raises(ValueError, match='value must be "\\*" or a list'):
            self._load(tmp_path, {"certbot": {"10.0.0.1": value}})

    def test_unparsable_hostname_matters_only_to_dotless_keys(self, tmp_path):
        hostname = "x" * 64
        maps = self._load(tmp_path, {"c": {"h.example.net": "*"}}, hostname=hostname)
        assert maps == {"c": {_name("h.example.net."): "*"}}
        with pytest.raises(ValueError, match="has no domain"):
            self._load(tmp_path, {"c": {"h": "*"}}, hostname=hostname)

    @pytest.mark.parametrize(
        "key", ["host.example.net", "host.example.net.", "HOST.Example.Net"]
    )
    def test_dotted_name_is_taken_as_fully_qualified(self, tmp_path, key):
        maps = self._load(tmp_path, {"certbot": {key: ["a.example.com"]}})["certbot"]
        assert maps == {_name("host.example.net."): ["a.example.com"]}
        (name,) = maps
        assert name.is_absolute()

    def test_dotless_name_gets_the_host_domain(self, tmp_path):
        maps = self._load(tmp_path, {"certbot": {"dtn-2": "*"}})["certbot"]
        assert maps == {_name("dtn-2.example.org."): "*"}

    def test_dotless_name_without_host_domain_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="'dtn-2' has no domain") as exc_info:
            self._load(tmp_path, {"certbot": {"dtn-2": "*"}}, hostname="dns1")
        assert "this host's name 'dns1'" in str(exc_info.value)

    def test_dotted_name_needs_no_host_domain(self, tmp_path):
        maps = self._load(tmp_path, {"c": {"h.example.net": "*"}}, hostname="dns1")
        assert maps == {"c": {_name("h.example.net."): "*"}}

    @pytest.mark.parametrize(
        "key", ["10.0.0.256", "1.2.3", "host.123", ".", "a..b", "x" * 64 + ".com"]
    )
    def test_implausible_name_is_rejected(self, tmp_path, key):
        with pytest.raises(ValueError, match=re.escape(repr(key))):
            self._load(tmp_path, {"certbot": {key: "*"}})

    @pytest.mark.parametrize(
        ("first", "second"),
        [("Host.example.org", "host.example.org."), ("dtn-2", "dtn-2.example.org")],
    )
    def test_keys_naming_the_same_host_are_rejected(self, tmp_path, first, second):
        content = f'{{"certbot": {{"{first}": "*", "{second}": ["a.example.com"]}}}}'
        with pytest.raises(ValueError, match="both name") as exc_info:
            self._load(tmp_path, content)
        assert repr(first) in str(exc_info.value)
        assert repr(second) in str(exc_info.value)

    def test_same_name_under_different_signers_is_fine(self, tmp_path):
        signers = self._load(
            tmp_path, {"a": {"h.example.net": "*"}, "b": {"h.example.net": "*"}}
        )
        assert set(signers) == {"a", "b"}

    @pytest.mark.parametrize(
        "content",
        ["not json", "[]", '{"certbot": []}', '{"certbot": "10.0.0.1"}'],
    )
    def test_malformed_file_raises_value_error(self, tmp_path, content):
        with pytest.raises(ValueError):
            self._load(tmp_path, content)

    def test_missing_file_raises_os_error(self, tmp_path):
        with pytest.raises(OSError):
            nap.load_signer_maps(str(tmp_path / "absent.json"), self.HOSTNAME)


class TestHostDomain:
    @pytest.mark.parametrize(
        ("hostname", "expected"),
        [
            ("dns1.example.org", "example.org."),
            ("dns1.example.org.", "example.org."),
            ("dns1.org", "org."),
            ("dns1", None),
            ("", None),
            ("x" * 64 + ".example.org", None),
        ],
    )
    def test_derives(self, hostname, expected):
        domain = nap._host_domain(hostname)
        assert (domain and str(domain)) == expected


class TestVerifyMapNames:
    PROBE = re.compile(r"_named-acme-policy-probe-[0-9a-f]{8}\.example\.org\.\Z")

    def test_checks_only_name_keys_and_logs_their_addresses(self, caplog):
        caplog.set_level("INFO")
        resolver = FakeResolver(
            raise_on_a=dns.resolver.NXDOMAIN(),
            name_a_records={"h.example.org.": ["10.0.0.1"]},
        )
        signers = {"certbot": {"10.0.0.2": "*", _name("h.example.org."): "*"}}
        assert nap.verify_map_names(signers, resolver) == []
        looked_up = [str(name) for name, _ in resolver.calls]
        assert looked_up[0] == "h.example.org."
        assert self.PROBE.match(looked_up[1])
        assert len(looked_up) == 2
        assert "map name h.example.org. resolves to ['10.0.0.1']" in caplog.text

    def test_probe_without_a_record_is_no_wildcard(self):
        # NoAnswer: the zone's wildcard, if any, has no A record.
        resolver = FakeResolver(name_a_records={"h.example.org.": ["10.0.0.1"]})
        assert (
            nap.verify_map_names({"c": {_name("h.example.org."): "*"}}, resolver) == []
        )

    def test_wildcard_zone_is_reported(self):
        # Even the misspelled name resolves, through the zone's wildcard.
        resolver = FakeResolver(a_records=["192.0.2.80"])
        signers = {"certbot": {_name("k8s-wroker-2.example.org."): "*"}}
        (failure,) = nap.verify_map_names(signers, resolver)
        assert failure.startswith(
            "signer 'certbot': k8s-wroker-2.example.org.: its zone has a wildcard A"
            " record (_named-acme-policy-probe-"
        )
        assert "resolves to ['192.0.2.80']), so a misspelling" in failure

    def test_failed_probe_is_reported(self):
        resolver = FakeResolver(
            raise_on_a=dns.exception.Timeout(),
            name_a_records={"h.example.org.": ["10.0.0.1"]},
        )
        (failure,) = nap.verify_map_names(
            {"c": {_name("h.example.org."): "*"}}, resolver
        )
        assert "h.example.org.: wildcard check of _named-acme-policy-probe-" in failure
        assert "failed: Timeout" in failure

    def test_reports_every_failure_with_its_signer(self):
        resolver = FakeResolver(
            raise_on_a=dns.resolver.NXDOMAIN(),
            name_a_records={
                "ok.example.org.": ["10.0.0.1"],
                "gone.example.org.": dns.resolver.NXDOMAIN(),
                "v6.example.org.": [],
            },
        )
        signers = {
            "a": {_name("ok.example.org."): "*", _name("gone.example.org."): "*"},
            "b": {_name("v6.example.org."): "*"},
        }
        assert nap.verify_map_names(signers, resolver) == [
            "signer 'a': gone.example.org.: NXDOMAIN: " + str(dns.resolver.NXDOMAIN()),
            "signer 'b': v6.example.org.: NoAnswer: " + str(dns.resolver.NoAnswer()),
        ]


class TestMainSignerMaps:
    def _run_main(self, monkeypatch, capsys, maps_path):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "named-acme-policy.py",
                "--socket",
                "/x",
                "--dns",
                "192.0.2.1",
                "--signer-maps",
                str(maps_path),
            ],
        )
        monkeypatch.setattr(socket, "gethostname", lambda: "dns1.example.org")
        with pytest.raises(SystemExit) as exc_info:
            nap.main()
        return exc_info.value.code, capsys.readouterr().err

    def test_unresolvable_name_aborts_startup(self, monkeypatch, capsys, tmp_path):
        def query(self, name, rdtype):
            if str(name) in ("google.com", "ok.example.net."):
                return [_rdata("A", "192.0.2.10")]
            raise dns.resolver.NXDOMAIN

        monkeypatch.setattr(dns.resolver.Resolver, "query", query)
        maps_path = tmp_path / "maps.json"
        maps_path.write_text('{"certbot": {"dtn-2": "*", "ok.example.net": "*"}}')
        code, err = self._run_main(monkeypatch, capsys, maps_path)
        assert code == 1
        assert "--signer-maps names failed checks:" in err
        assert "signer 'certbot': dtn-2.example.org.: NXDOMAIN" in err
        assert "ok.example.net" not in err

    def test_malformed_file_is_a_usage_error_before_any_lookup(
        self, monkeypatch, capsys, tmp_path
    ):
        def query(*args, **kwargs):
            raise AssertionError("main() reached a DNS lookup")

        monkeypatch.setattr(dns.resolver.Resolver, "query", query)
        maps_path = tmp_path / "maps.json"
        maps_path.write_text('{"certbot": {"10.0.0.256": "*"}}')
        code, err = self._run_main(monkeypatch, capsys, maps_path)
        assert code == 2
        assert f"--signer-maps {maps_path}: '10.0.0.256'" in err


class TestIsNonGlobal:
    @pytest.mark.parametrize(
        ("addr", "expected"),
        [
            ("10.0.0.1", True),
            ("100.64.1.1", True),  # CGNAT: neither private nor global
            ("fd00::1", True),
            ("144.92.100.35", False),
            ("2001:4860:4860::8888", False),
            # dnspython 1.x passes this through; ipaddress rejects it.
            ("010.0.0.1", False),
        ],
    )
    def test_classifies(self, addr, expected):
        assert nap._is_non_global(addr) is expected


def _capture_exiting_output(argv, capsys):
    """Run the parser on argv, expecting it to print and exit; return (stdout, code)."""
    with pytest.raises(SystemExit) as exc_info:
        nap.build_parser().parse_args(argv)
    return capsys.readouterr().out, exc_info.value.code


class TestDetailedHelp:
    def test_works_without_the_required_socket_argument(self, capsys):
        # The action must fire during parsing, like -h does; a check after
        # parse_args() would be unreachable because --socket is required.
        out, code = _capture_exiting_output(["--detailed-help"], capsys)
        assert code in (0, None)
        assert out.strip()

    def test_socket_is_still_required_otherwise(self, capsys):
        _, code = _capture_exiting_output([], capsys)
        assert code != 0

    def test_lines_stay_under_100_characters(self):
        too_long = [ln for ln in nap.DETAILED_HELP.splitlines() if len(ln) >= 100]
        assert not too_long

    def test_is_broken_into_blank_line_separated_paragraphs(self):
        assert "\n\n" in nap.DETAILED_HELP

    def test_covers_each_section_the_epilog_used_to_carry(self):
        for heading in (
            "NAMED(8) INTEGRATION",
            "WHY A SEPARATE DNS SERVER",
            "SECURITY MODEL",
            "SIGNER MAPS FILE",
        ):
            assert heading in nap.DETAILED_HELP

    def test_states_the_decision_budget(self):
        text = " ".join(nap.DETAILED_HELP.split())
        assert f"about {nap.DECISION_BUDGET:g} seconds at most" in text

    def test_bind9_url_is_not_split_across_lines(self):
        # argparse's HelpFormatter used to hyphenate this URL mid-path.
        url = "https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy"
        assert any(ln.strip() == url for ln in nap.DETAILED_HELP.splitlines())


class TestHelpOutput:
    def test_has_no_dangling_references_to_the_removed_epilog(self, capsys):
        out, _ = _capture_exiting_output(["--help"], capsys)
        assert "epilog" not in out.lower()
        assert not re.search(r"note \(?[A-D]\)?", out, re.IGNORECASE)

    def test_does_not_advertise_empty_defaults(self, capsys):
        out, _ = _capture_exiting_output(["--help"], capsys)
        assert "default: None" not in out

    def test_points_at_detailed_help(self, capsys):
        out, _ = _capture_exiting_output(["--help"], capsys)
        assert "--detailed-help" in out

    def test_dns_help_states_the_real_default(self, capsys):
        # The default is spelled out by hand now that
        # ArgumentDefaultsHelpFormatter is gone; guard against it drifting.
        default = nap.build_parser().parse_args(["--socket", "/nonexistent"]).dns
        out, _ = _capture_exiting_output(["--help"], capsys)
        assert f"default: {' '.join(default)}" in " ".join(out.split())


class TestModuleLoader:
    def test_does_not_execute_stale_bytecode(self, tmp_path):
        # CPython validates a cached .pyc on (source size, source mtime in
        # whole seconds). Edit a file without changing its length, inside the
        # same second as the last load, and both fields still match -- so a
        # cache-consulting loader would hand back the previous version.
        probe = tmp_path / "stale-probe.py"
        probe.write_text("VALUE = 'aaa'\n")
        assert _load_module(probe).VALUE == "aaa"

        before = probe.stat()
        probe.write_text("VALUE = 'bbb'\n")  # same byte count
        os.utime(probe, (before.st_atime, before.st_mtime))
        assert _load_module(probe).VALUE == "bbb"


def _local_non_loopback_address():
    """An address assigned to this host other than loopback, via iproute2, which
    is independent of the method under test; None if unavailable.
    """
    try:
        out = subprocess.run(
            ["ip", "-j", "addr"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            universal_newlines=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    for iface in json.loads(out):
        for info in iface.get("addr_info", []):
            ip = ipaddress.ip_address(info["local"])
            if not (ip.is_loopback or ip.is_link_local):
                return str(ip)
    return None


class TestIsLocalAddress:
    @pytest.mark.parametrize(
        "addr",
        [
            "127.0.0.1",
            "127.0.0.53",  # systemd-resolved's stub: any of 127/8, not just .1
            "::1",
            "0.0.0.0",  # routed to loopback
            "::",
            "::ffff:127.0.0.1",  # IPv4-mapped loopback
        ],
    )
    def test_loopback_and_unspecified_are_local(self, addr):
        assert nap._is_local_address(addr) is True

    @pytest.mark.parametrize(
        "addr",
        [
            "192.0.2.1",  # TEST-NET-1
            "2001:db8::1",  # documentation prefix; likely unroutable here
            "::ffff:192.0.2.1",
            "fe80::1",  # link-local without a scope: connect() fails
        ],
    )
    def test_foreign_addresses_are_not_local(self, addr):
        assert nap._is_local_address(addr) is False

    def test_interface_address_is_local(self):
        addr = _local_non_loopback_address()
        if addr is None:
            pytest.skip("no non-loopback address, or no iproute2, on this host")
        assert nap._is_local_address(addr) is True

    def test_ignores_ip_nonlocal_bind(self, monkeypatch):
        # Under that sysctl any bind() succeeds; make it so here and check
        # that the result doesn't rely on bind().
        monkeypatch.setattr(socket.socket, "bind", lambda self, addr: None)
        assert nap._is_local_address("192.0.2.1") is False


class TestDnsArgument:
    def _parse(self, *dns):
        return nap.build_parser().parse_args(["--socket", "/x", "--dns", *dns])

    def test_accepts_ipv4_and_ipv6(self):
        assert self._parse("192.0.2.1", "2001:db8::1").dns == [
            "192.0.2.1",
            "2001:db8::1",
        ]

    def test_rejects_hostname(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            self._parse("dns.google")
        assert exc_info.value.code == 2
        assert "not an IP address: 'dns.google'" in capsys.readouterr().err


class TestMainRejectsLocalDns:
    @pytest.fixture
    def no_network(self, monkeypatch):
        """Fail the test if main() gets as far as its resolver probe."""

        def query(*args, **kwargs):
            raise AssertionError("main() reached a DNS lookup")

        monkeypatch.setattr(dns.resolver.Resolver, "query", query)

    def _run_main(self, monkeypatch, capsys, *dns):
        monkeypatch.setattr(
            sys, "argv", ["named-acme-policy.py", "--socket", "/x", "--dns", *dns]
        )
        with pytest.raises(SystemExit) as exc_info:
            nap.main()
        return exc_info.value.code, capsys.readouterr().err

    @pytest.mark.usefixtures("no_network")
    def test_exits_before_any_lookup(self, monkeypatch, capsys):
        code, err = self._run_main(monkeypatch, capsys, "127.0.0.1")
        assert code == 2
        assert "--dns must not point at this host (127.0.0.1)" in err

    @pytest.mark.usefixtures("no_network")
    def test_one_local_among_several_suffices_and_is_named(self, monkeypatch, capsys):
        code, err = self._run_main(
            monkeypatch, capsys, "192.0.2.1", "::1", "192.0.2.2", "127.0.0.53"
        )
        assert code == 2
        assert "(::1 127.0.0.53)" in err

    def test_remote_dns_passes_the_check(self, monkeypatch, capsys):
        # Stop at the resolver probe, which comes right after the check.
        def query(*args, **kwargs):
            raise dns.exception.Timeout

        monkeypatch.setattr(dns.resolver.Resolver, "query", query)
        code, err = self._run_main(monkeypatch, capsys, "192.0.2.1")
        assert code == 1
        assert "--dns servers failed test" in err
