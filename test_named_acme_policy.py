"""Unit tests for named-acme-policy.py.

The script's filename contains hyphens, so it can't be `import`ed normally;
it is loaded via `importlib` from `conftest.py`-free fixtures below instead.
"""

import importlib.util
from pathlib import Path

import dns.resolver
import pytest

MODULE_PATH = Path(__file__).parent / "named-acme-policy.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("named_acme_policy", MODULE_PATH)
    assert spec and spec.loader
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
