#!/usr/bin/env python3
"""External update-policy decider daemon for named(8): grants dynamic DNS
updates that belong to an ACME DNS-01 challenge, such as certbot's.

DETAILED_HELP below is the user-facing documentation (named(8) setup, security
model). Keep operator-facing explanation there rather than duplicating it here.
"""

import argparse
import concurrent.futures
import copy
import ipaddress
import json
import logging
import re
import secrets
import shutil
import socket
import struct
import sys
import time
from pathlib import Path

import dns.exception
import dns.name
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

# Wall-clock seconds the lookups behind one decision may take in total. named(8)
# blocks on every decision; this is three of main()'s 0.5 s lookup lifetimes, for
# the existence check, the --signer-maps names (looked up in parallel) and the
# reverse lookup. The name step must leave a lifetime's worth for the last.
DECISION_BUDGET = 1.5
# Most --signer-maps names looked up at once for one decision.
MAX_PARALLEL_LOOKUPS = 16

DETAILED_HELP = """\
named-acme-policy -- external update-policy decider for ACME DNS-01 challenges


NAMED(8) INTEGRATION

  A zone is delegated to this daemon with an "external" update-policy rule naming
  the daemon's socket. For the rule syntax, see the BIND 9 reference manual:

  https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy


WHY A SEPARATE DNS SERVER

  named(8) evaluates an external update-policy decision synchronously: it blocks
  until this daemon answers, and that includes blocking the name lookups this
  daemon makes to reach a decision. Pointing --dns at the local named(8) therefore
  deadlocks. It must name a different resolver.

  The daemon refuses to start if any --dns address belongs to this host, loopback
  and 0.0.0.0 included, even if what listens there isn't named(8). It can't detect
  indirect loops: a resolver elsewhere that forwards to this named(8), a NAT or
  port forward leading back here, or a VIP this host may take over later.

  For the reverse lookup to work for hosts that send from private addresses
  (10.0.0.0/8 and the like), that resolver must also serve their reverse zones.
  Public resolvers, including the 8.8.8.8 default, answer NXDOMAIN for those.


SECURITY MODEL

  A request is granted only when all of the following hold:

    * the resource record name starts with "_acme-challenge." and its type is TXT;

    * the request is signed by a signer present in --signer-maps (a request from
      an unlisted signer is always denied);

    * the domain being updated (the part after "_acme-challenge.") exists, meaning
      it has an A record, possibly via CNAME. This is checked before any of the
      ways below, so it binds static maps too, "*" included. A lookup that fails
      for any reason, resolver trouble included, denies the request;

    * the source address is tied to the domain being updated, in any one of three
      ways:

        - --signer-maps maps the source address, or a host name whose A records
          include it, to that domain, or to "*";

        - the domain resolves to the source address, which covers one-to-one and
          round-robin hosts;

        - the source address reverse-resolves to the domain, which covers
          multi-homed hosts that send from an internal address while the domain
          publishes an external one.


SIGNER MAPS FILE

  --signer-maps takes a JSON file of per-signer static source-to-domain overrides:

      {"<signer>": {"<ip or host name>": ["<fqdn>", ...]}}

  A source may map to the literal "*" rather than a list, which grants that
  signer any existing domain from that source. Such an entry confers blanket
  _acme-challenge write access in every zone whose update-policy points at this
  daemon's socket, so keep it out of zones it has no business in.

  A host name matches a request whose source address is among the name's A
  records, looked up through --dns each time it is consulted. Hence IPv6 sources
  never match one, and whoever can change those records, by any update-policy
  rule or otherwise, wields the entry's grant. That includes whoever controls the
  target of a CNAME the name points to, as the lookup follows it.

  A name with a dot is taken as fully qualified; a dotless one gets this host's
  domain appended, taken from its hostname (as gethostname(2) reports it), not
  from resolv.conf. Names must consist of letters, digits and hyphens.

  The daemon refuses to start if a name fails to resolve, or if its zone answers
  for names that don't exist (a wildcard A record), as then a misspelled name
  would resolve too. Later lookup failures are logged as errors and skip just
  that entry. Each value must be "*" or a list of domains, and each source may
  appear only once per signer.

  The lookups behind one decision take about 1.5 seconds at most; ones that run
  out of time fail.

  Without --signer-maps the sole accepted signer is "certbot" with no static
  overrides, meaning every request must pass the address checks above.\
"""


def unpack_req_msg(data):
    r"""Convert a named(8) update request message into the fields we judge on.

    The wire format is documented under the "external" update-policy rule type:
    https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy
    An 8-byte header precedes NUL-terminated fields; the first four interest us
    (rr stands for resource record):

        b'\x00\x00\x00\x01\x00\x00\x00bcertbot\x00_acme-challenge.bookstack.i'
        b'cecube.wisc.edu\x00144.92.100.35\x00TXT\x00certbot/165/7089\x00\x00\x00\x00\x00'

    -> signer 'certbot', rr_name '_acme-challenge.bookstack.icecube.wisc.edu',
       src_addr '144.92.100.35', rr_type 'TXT'
    """
    signer, rr_name, src_addr, rr_type = data[8:].split(b"\x00")[0:4]
    return {
        "signer": signer.decode(),
        "src_addr": src_addr.decode(),
        "rr_name": rr_name.decode(),
        "rr_type": rr_type.decode(),
    }


def is_valid_acme_update(msg, signers, resolver):
    """Decide whether `msg`, as returned by `unpack_req_msg`, is an ACME DNS-01
    update this daemon should grant. DETAILED_HELP states the rules.
    """
    deadline = time.monotonic() + DECISION_BUDGET
    subdomain, domain = msg["rr_name"].split(".", 1)
    if subdomain != "_acme-challenge" or msg["rr_type"] != "TXT":
        logger.info(f"{msg} doesn't look related to an ACME challenge.")
        return False
    maps = signers.get(msg["signer"])
    if maps is None:
        logger.info(f"Request {msg} signed by unconfigured signer {msg['signer']!r}.")
        return False

    # The domain must exist, meaning it has an A record (possibly via CNAME),
    # before any grant path is considered, static maps and "*" included. Failing
    # to find out, e.g. because --dns is unreachable, denies as well. Lookup
    # failures deny here, logged with what was being looked up, rather than
    # propagating to main()'s generic exception handler.
    # Absolute, because query() applies the search list to relative names, and
    # even Resolver(configure=False) derives one from the host's FQDN: a missing
    # foo.example.org would be retried as foo.example.org.<our domain>.
    domain_name = dns.name.from_text(domain)
    try:
        domain_addrs = [str(a) for a in _query(resolver, domain_name, "A", deadline)]
    except dns.exception.DNSException as e:
        _log_lookup_failure(f"Existence check (A lookup) of {domain}", e)
        return False

    src_addr = msg["src_addr"]
    if _covers(maps.get(_normalize_ip(src_addr)), domain):
        logger.info(f"Granting {msg} via static map for signer {msg['signer']!r}.")
        return True

    # No IP-keyed override. The remaining ways in, cheapest first: the domain
    # resolves to the source address (1-to-1 and round-robin hosts), a host-name
    # key resolves to it, or the source address reverse-resolves to the domain
    # (multi-homed hosts, which send from an internal address while the domain
    # publishes an external one).
    if src_addr in domain_addrs:
        logger.info(f"Granting {msg} via forward lookup for signer {msg['signer']!r}.")
        return True

    names = []
    if _is_ipv4(src_addr):  # name keys hold A records only
        names = [
            k
            for k, v in maps.items()
            if isinstance(k, dns.name.Name) and _covers(v, domain)
        ]
    # Stop in time for the reverse lookup, so that hung name lookups can't deny
    # a host it would grant.
    names_deadline = deadline - resolver.lifetime
    matched, name_addrs = _matching_name_key(names, src_addr, resolver, names_deadline)
    if matched is not None:
        logger.info(
            f"Granting {msg} via static map name {matched} for signer {msg['signer']!r}."
        )
        return True

    # Only now is the reverse lookup needed: doing it earlier would let its
    # failure deny a request that a cheaper way above already justifies.
    rev_name = dns.reversename.from_address(src_addr)  # e.g. 8.8.8.8.in-addr.arpa.
    try:
        ptrs = _query(resolver, rev_name, "PTR", deadline)
        src_ptr_names = [ptr.target for ptr in ptrs]
    except dns.exception.DNSException as e:
        # Public resolvers answer NXDOMAIN for non-global reverse zones.
        hint = ""
        if isinstance(e, dns.resolver.NXDOMAIN) and _is_non_global(src_addr):
            hint = " (non-global address: does --dns serve its reverse zone?)"
        _log_lookup_failure(f"Reverse lookup of {src_addr}", e, hint)
        return False
    # Name comparison, unlike str comparison, ignores case as DNS does.
    if domain_name in src_ptr_names:
        logger.info(f"Granting {msg} via reverse lookup for signer {msg['signer']!r}.")
        return True
    names_info = "".join(f", {n} -> {a}" for n, a in name_addrs.items())
    logger.info(
        f"Source check failed: {domain} -> {domain_addrs}{names_info},"
        f" {src_addr} -> {[str(n) for n in src_ptr_names]}"
    )
    return False


def _query(resolver, name, rdtype, deadline):
    """`resolver.query(name, rdtype)`, its lifetime clipped to end by `deadline`
    (a time.monotonic() value). Running out of time raises Timeout, saying so.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise dns.exception.Timeout("decision budget exhausted")
    # dnspython 1.x query() takes no per-call lifetime, so clip a copy's.
    clipped = copy.copy(resolver)
    clipped.lifetime = min(resolver.lifetime, remaining)
    try:
        return clipped.query(name, rdtype)
    except dns.exception.Timeout:
        if clipped.lifetime < resolver.lifetime:
            msg = f"decision budget exhausted ({remaining:.3f} s were left)"
            raise dns.exception.Timeout(msg) from None
        raise


def _covers(allowed, domain):
    """Whether signer-map value `allowed` ("*" or a list of domains) grants
    `domain`. Anything else, e.g. a bare domain string, grants nothing.
    """
    return allowed == "*" or (isinstance(allowed, list) and domain in allowed)


def _matching_name_key(names, src_addr, resolver, deadline):
    """Look up the A records of host names `names` in parallel, by `deadline`.

    Return the first name found to have `src_addr` among them, or None, along
    with what each name looked up so far resolved to, or the type of its failure.
    A failed lookup only skips its name, but is an ERROR since every name resolved
    at startup.
    """
    name_addrs = {}
    if not names:
        return None, name_addrs
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(names), MAX_PARALLEL_LOOKUPS)
    )
    futures = {
        executor.submit(_query, resolver, name, "A", deadline): name for name in names
    }
    try:
        timeout = max(0, deadline - time.monotonic())
        for future in concurrent.futures.as_completed(futures, timeout=timeout):
            name = futures[future]
            try:
                addrs = [str(a) for a in future.result()]
            except dns.exception.DNSException as e:
                logger.error(
                    f"Signer-map name lookup of {name} failed: {type(e).__name__}: {e}"
                )
                name_addrs[name] = type(e).__name__
                continue
            name_addrs[name] = addrs
            if src_addr in addrs:
                return name, name_addrs
    except concurrent.futures.TimeoutError:
        pending = " ".join(str(n) for f, n in futures.items() if not f.done())
        logger.error(f"Decision budget exhausted awaiting name lookups: {pending}")
    finally:
        # Don't wait for the rest: queued lookups are cancelled, and running ones
        # end by `deadline` anyway. (Python 3.6 lacks shutdown's cancel_futures.)
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False)
    return None, name_addrs


def _normalize_ip(addr):
    """`addr` in ipaddress's canonical form, as signer-map IP keys are stored,
    since its str() of e.g. IPv4-mapped IPv6 addresses varies across Python
    versions. Anything that isn't an IP address is returned as is.
    """
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return addr


def _is_ipv4(addr):
    """Whether `addr` is an IPv4 address."""
    try:
        return ipaddress.ip_address(addr).version == 4
    except ValueError:
        return False


def load_signer_maps(path, hostname):
    """Load the --signer-maps JSON file at `path`; DETAILED_HELP gives its format.

    IP-address keys are normalized, e.g. 2001:DB8:0::1 to 2001:db8::1, to compare
    equal to named(8)'s source addresses. Any other key is a host name, converted
    to an absolute dns.name.Name: a dotted one is taken as already fully
    qualified, a dotless one is qualified with the domain of `hostname`, this
    host's name. Raises OSError if the file can't be read, ValueError if it is
    malformed.
    """
    host_domain = _host_domain(hostname)
    with open(path) as f:
        raw = json.load(f, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(raw, dict):
        raise ValueError("top level must be an object of signers")  # noqa: TRY004 -- bad file data
    signers = {}
    for signer, entries in raw.items():
        if not isinstance(entries, dict):
            raise ValueError(f"signer {signer!r}: entries must be an object")  # noqa: TRY004 -- bad file data
        maps = signers[signer] = {}
        spelled = {}  # how each key was written, to name both sides of a clash
        for key, allowed in entries.items():
            source = _parse_source(key, host_domain, hostname)
            if not _is_valid_value(allowed):
                raise ValueError(
                    f"signer {signer!r}, {key!r}: value must be"
                    f' "*" or a list of domains, not {allowed!r}'
                )
            if source in maps:
                raise ValueError(
                    f"signer {signer!r}: {key!r} and {spelled[source]!r} both name {source}"
                )
            maps[source] = allowed
            spelled[source] = key
    return signers


def _reject_duplicate_keys(pairs):
    """json object_pairs_hook: a dict of `pairs`, which may not repeat a key."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _is_valid_value(allowed):
    """Whether signer-map value `allowed` is "*" or a list of domain strings."""
    return allowed == "*" or (
        isinstance(allowed, list) and all(isinstance(d, str) for d in allowed)
    )


# A host name label: letters, digits and inner hyphens (RFC 1123).
_HOSTNAME_LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\Z")


def _parse_source(key, host_domain, hostname):
    """Convert signer-map key `key` as described in `load_signer_maps`, where
    `host_domain` is the domain of `hostname`, or None if it has none.
    """
    try:
        return str(ipaddress.ip_address(key))
    except ValueError:
        pass
    # Keys like "10.0.0.0/24", "10.0.0.1:53" or "_comment" are no host names.
    labels = key[:-1].split(".") if key.endswith(".") else key.split(".")
    if not all(_HOSTNAME_LABEL.match(label) for label in labels):
        raise ValueError(
            f"{key!r} is neither an IP address nor a host name"
            " (letters, digits and hyphens)"
        )
    if "." in key:
        origin = dns.name.root
    elif host_domain is None:
        raise ValueError(
            f"{key!r} has no domain, and this host's name {hostname!r} has none"
            " to qualify it with"
        )
    else:
        origin = host_domain
    try:
        name = dns.name.from_text(key, origin=origin)
    except dns.exception.DNSException as e:
        raise ValueError(
            f"{key!r} is neither an IP address nor a valid name: {e}"
        ) from None
    # No top-level domain is numeric, so this is most likely a mistyped IP, e.g.
    # 10.0.0.256, which deserves a better error than its failed startup lookup.
    if name.labels[-2].isdigit():
        raise ValueError(f"{key!r} is neither an IP address nor a plausible host name")
    return name


def _host_domain(hostname):
    """The domain of `hostname` as a dns.name.Name, None if it has none, deriving
    it as dnspython does for its search list.
    """
    try:
        labels = dns.name.from_text(hostname).labels[1:]
    # E.g. a label over 63 octets: no usable domain, which matters only if a
    # dotless key needs one, and then _parse_source names the hostname.
    except dns.exception.DNSException:
        return None
    return dns.name.Name(labels) if len(labels) > 1 else None


def verify_map_names(signers, resolver):
    """Check that every host-name key in `signers` resolves, and that its zone
    has no wildcard A record, which would make a misspelled name resolve as
    well. Log what each name resolves to; return a message for each that fails.
    """
    failures = []
    for signer, maps in signers.items():
        for key in maps:
            if not isinstance(key, dns.name.Name):
                continue
            try:
                addrs = [str(a) for a in resolver.query(key, "A")]
            except dns.exception.DNSException as e:
                failures.append(f"signer {signer!r}: {key}: {type(e).__name__}: {e}")
                continue
            # A sibling no one would create resolves only through a wildcard.
            probe = dns.name.Name(
                (f"_named-acme-policy-probe-{secrets.token_hex(4)}".encode(),)
            ).concatenate(key.parent())
            try:
                wildcard_addrs = [str(a) for a in resolver.query(probe, "A")]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                logger.info(f"Signer {signer!r} map name {key} resolves to {addrs}")
                continue
            except dns.exception.DNSException as e:
                failures.append(
                    f"signer {signer!r}: {key}: wildcard check of {probe} failed:"
                    f" {type(e).__name__}: {e}"
                )
                continue
            failures.append(
                f"signer {signer!r}: {key}: its zone has a wildcard A record"
                f" ({probe} resolves to {wildcard_addrs}), so a misspelling of"
                " it would resolve too"
            )
    return failures


def _log_lookup_failure(what, exc, hint=""):
    """Log a failed lookup. Resolver trouble (timeouts, every server failing) is
    an ERROR with dnspython's message, which names each server and its answer;
    a negative answer (NXDOMAIN, NoAnswer) is a WARNING that needs no detail.
    """
    if isinstance(exc, (dns.exception.Timeout, dns.resolver.NoNameservers)):
        logger.error(f"{what} failed: {type(exc).__name__}: {exc}")
    else:
        logger.warning(f"{what} failed: {type(exc).__name__}{hint}")


def _is_local_address(addr):
    """Whether IP address `addr` reaches this host: loopback, unspecified (which
    the kernel routes to loopback), or assigned to one of its interfaces.

    The last is tested by connecting a UDP socket, which sends nothing, and
    checking that the kernel picked `addr` itself as the source address, which it
    does only for local destinations. Unlike test-binding to `addr`, this holds
    when the ip_nonlocal_bind sysctl lets any address be bound.
    """
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return True
    try:
        family, type_, proto, _, sockaddr = socket.getaddrinfo(
            str(ip), 53, type=socket.SOCK_DGRAM, flags=socket.AI_NUMERICHOST
        )[0]
        with socket.socket(family, type_, proto) as s:
            s.connect(sockaddr)
            return ipaddress.ip_address(s.getsockname()[0]) == ip
    # No route, no IPv6 support, a link-local address lacking a scope: none of
    # these can be an address of ours that a resolver would use.
    except OSError:
        return False


def _ip_address(value):
    """argparse type: `value` unchanged if it is an IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IP address: {value!r}") from None
    return value


def _is_non_global(addr):
    """Whether `addr` is an IP address outside globally routable space."""
    try:
        return not ipaddress.ip_address(addr).is_global
    # dnspython 1.x accepts addresses ipaddress rejects, e.g. 010.0.0.1.
    except ValueError:
        return False


class _DetailedHelpAction(argparse.Action):
    """Print DETAILED_HELP and exit, mirroring how argparse implements -h.

    Acting during parsing rather than after it is what lets --detailed-help be
    used on its own, despite --socket being required. Printing directly also
    keeps the text away from argparse's HelpFormatter, which would collapse the
    paragraphs into one block.
    """

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(DETAILED_HELP)
        parser.exit()


def build_parser():
    """Build the command-line parser, kept out of `main` so tests can reach it."""
    parser = argparse.ArgumentParser(
        description="External named(8) update-policy decider daemon that grants "
        "dynamic DNS (RFC 2136) update requests belonging to an Automatic "
        "Certificate Management Environment (ACME) DNS-01 challenge, such as those "
        "made by Let's Encrypt's certbot client. It enforces a somewhat stricter "
        "permissions model than named(8)'s built-in update-policy rules allow; run "
        "with --detailed-help for that model and for setup notes.",
    )
    parser.add_argument(
        "--socket",
        metavar="SOCKET_PATH",
        required=True,
        help="path to the Unix socket file for communication with named(8)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="log to PATH in addition to stderr",
    )
    parser.add_argument(
        "--dns",
        metavar="IP",
        type=_ip_address,
        nargs="+",
        default=["8.8.8.8", "8.8.4.4"],
        help="resolver(s) used to verify request source addresses; must not be "
        "the named(8) this daemon serves, which would deadlock, so addresses of "
        "this host are rejected (default: 8.8.8.8 8.8.4.4)",
    )
    parser.add_argument(
        "--signer-maps",
        metavar="PATH",
        help="JSON file of per-signer static source-to-domain overrides, sources "
        "being IP addresses or host names; a signer it "
        'omits is denied outright (default: accept signer "certbot" only, with no '
        "overrides)",
    )
    parser.add_argument(
        "--detailed-help",
        action=_DetailedHelpAction,
        default=argparse.SUPPRESS,
        help="show the security model and named(8) setup notes, and exit",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    # The resolver probe below would pass against the local named(8): the deadlock
    # only strikes once named(8) awaits a decision, so it must be caught here.
    local = [addr for addr in args.dns if _is_local_address(addr)]
    if local:
        parser.error(
            f"--dns must not point at this host ({' '.join(local)}): named(8) "
            "blocks while awaiting our decisions, so it can't answer our lookups. "
            "See --detailed-help."
        )
    if args.signer_maps:
        try:
            signers = load_signer_maps(args.signer_maps, socket.gethostname())
        except (OSError, ValueError) as e:
            parser.error(f"--signer-maps {args.signer_maps}: {e}")
    else:
        signers = {"certbot": {}}

    logging.basicConfig(
        filename=args.log_file,
        level=logging.INFO,
        format="%(asctime)-23s %(levelname)s %(message)s",
    )
    if args.log_file:
        logging.getLogger().addHandler(logging.StreamHandler())

    # The protocol: named(8) writes a request to the socket, we write back 1 or 0.
    # It blocks on that answer, including on the lookups below, so these timeouts
    # are a latency budget for the whole server rather than mere error handling.
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = args.dns
    resolver.timeout = 0.25  # seconds to wait for a response from a server
    resolver.lifetime = 0.5  # seconds to spend trying to get an answer
    # Every lookup in this file uses the deprecated query() rather than
    # resolve(), which exists only from dnspython 2.0, so that the daemon keeps
    # working against the 1.x that long-lived distributions still ship.
    try:
        resolver.query("google.com", "A")
    except Exception as e:  # noqa: BLE001 -- any failure here should abort startup
        parser.exit(1, f"--dns servers failed test: {e}\n")

    failures = verify_map_names(signers, resolver)
    if failures:
        parser.exit(
            1,
            "--signer-maps names failed checks:\n  " + "\n  ".join(failures) + "\n",
        )

    socket_path = Path(args.socket)
    Path.mkdir(socket_path.parent, parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    socket_path.chmod(0o660)
    shutil.chown(str(socket_path), "named", "named")
    server.listen()

    while True:
        conn, _addr = server.accept()
        data = conn.recv(2**20)
        logger.info(f"Received request {data}")
        try:
            msg = unpack_req_msg(data)
        # Any decoding failure must deny the request, not crash the daemon,
        # since named(8) evaluates us synchronously for every DNS update.
        except Exception as e:  # noqa: BLE001
            logger.error(f"Denying request {data} because of decoding failure {e}")
            conn.send(struct.pack("!I", 0))
            continue
        else:
            logger.info(f"Unpacked request {msg}")
            try:
                grant = is_valid_acme_update(msg, signers, resolver)
            # Same fail-safe reasoning as above: never let validation crash the daemon.
            except Exception as e:  # noqa: BLE001
                logger.error(f"Validating {msg} raised an exception: {e}")
                grant = False
            if grant:
                logger.info(f"Granting request {msg}")
                conn.send(struct.pack("!I", 1))
            else:
                logger.info(f"Denying request {msg}")
                conn.send(struct.pack("!I", 0))
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
