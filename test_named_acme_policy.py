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
from pathlib import Path

import dns.exception
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
    """

    def __init__(
        self, a_records=(), ptr_records=(), raise_on_a=None, raise_on_ptr=None
    ):
        self.a_records = list(a_records)
        self.ptr_records = list(ptr_records)
        self.raise_on_a = raise_on_a
        self.raise_on_ptr = raise_on_ptr
        self.calls = []

    def query(self, name, rdtype):
        self.calls.append((name, rdtype))
        if rdtype == "A":
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
