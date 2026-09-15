"""Unit tests for named-acme-policy.py.

The script's hyphenated filename can't be `import`ed, so `_load_module` below
loads it through a custom loader that also skips the bytecode cache.
"""

import importlib.machinery
import importlib.util
import os
import re
from pathlib import Path

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
    (see note (B) in the script's --help epilog: a non-local resolver is
    required to avoid deadlock, since named(8) evaluates this synchronously
    against itself), so a single stub tracking both is enough.
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
            if self.raise_on_a is not None:
                raise self.raise_on_a
            return self.a_records
        if rdtype == "PTR":
            if self.raise_on_ptr is not None:
                raise self.raise_on_ptr
            return self.ptr_records
        raise AssertionError(f"unexpected rdtype {rdtype!r}")


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

    def test_static_map_hit_grants_without_dns_lookup(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        signers = {"certbot": {"10.0.0.1": ["other.example.org", "example.com"]}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is True
        assert resolver.calls == []

    def test_wildcard_static_map_entry_grants_any_domain(self):
        msg = {
            "signer": "k8s-certbot",
            "rr_name": "_acme-challenge.anything.example.net",
            "src_addr": "10.1.2.3",
            "rr_type": "TXT",
        }
        resolver = FakeResolver()
        signers = {"k8s-certbot": {"10.1.2.3": "*"}}
        assert nap.is_valid_acme_update(msg, signers, resolver) is True
        assert resolver.calls == []

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
        # module-level dns.resolver.query, per note (B) in the --help epilog.
        assert [(str(name), rdtype) for name, rdtype in resolver.calls] == [
            ("example.com", "A"),
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

    def test_forward_resolution_no_answer_denies(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(raise_on_a=dns.resolver.NoAnswer())
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False

    def test_forward_resolution_nxdomain_propagates(self):
        # NXDOMAIN is not a subclass of NoAnswer, so the except clause
        # doesn't catch it; the caller (main's request loop) is responsible
        # for treating any uncaught exception here as a denial.
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(raise_on_a=dns.resolver.NXDOMAIN())
        with pytest.raises(dns.resolver.NXDOMAIN):
            nap.is_valid_acme_update(msg, {"certbot": {}}, resolver)

    def test_ptr_lookup_no_answer_treated_as_empty_and_falls_back_to_forward(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(
            a_records=["10.0.0.1"], raise_on_ptr=dns.resolver.NoAnswer()
        )
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is True

    def test_ptr_lookup_no_answer_and_no_forward_match_denies(self):
        msg = {
            "signer": "certbot",
            "rr_name": "_acme-challenge.example.com",
            "src_addr": "10.0.0.1",
            "rr_type": "TXT",
        }
        resolver = FakeResolver(
            a_records=["203.0.113.5"], raise_on_ptr=dns.resolver.NoAnswer()
        )
        assert nap.is_valid_acme_update(msg, {"certbot": {}}, resolver) is False

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
