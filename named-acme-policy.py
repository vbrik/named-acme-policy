#!/usr/bin/env python3
"""External update-policy decider daemon for named(8): grants dynamic DNS
updates that belong to an ACME DNS-01 challenge, such as certbot's.

DETAILED_HELP below is the user-facing documentation (named(8) setup, security
model). Keep operator-facing explanation there rather than duplicating it here.
"""

import argparse
import ipaddress
import json
import logging
import shutil
import socket
import struct
import sys
from pathlib import Path

import dns.exception
import dns.name
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

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

        - --signer-maps maps the source address to that domain, or to "*";

        - the domain resolves to the source address, which covers one-to-one and
          round-robin hosts;

        - the source address reverse-resolves to the domain, which covers
          multi-homed hosts that send from an internal address while the domain
          publishes an external one.


SIGNER MAPS FILE

  --signer-maps takes a JSON file of per-signer static address-to-domain overrides:

      {"<signer>": {"<ip>": ["<fqdn>", ...]}}

  An address may map to the literal "*" rather than a list, which grants that
  signer any existing domain from that address. Such an entry confers blanket
  _acme-challenge write access in every zone whose update-policy points at this
  daemon's socket, so keep it out of zones it has no business in.

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
        domain_addrs = [str(a) for a in resolver.query(domain_name, "A")]
    except dns.exception.DNSException as e:
        _log_lookup_failure(f"Existence check (A lookup) of {domain}", e)
        return False

    src_addr = msg["src_addr"]
    allowed = maps.get(src_addr, [])
    if allowed == "*" or (isinstance(allowed, list) and domain in allowed):
        logger.info(f"Granting {msg} via static map for signer {msg['signer']!r}.")
        return True

    # No static override, so make the requestor prove it owns the domain: either
    # the domain resolves to the source address (1-to-1 and round-robin hosts), or
    # the source address reverse-resolves to the domain (multi-homed hosts, which
    # send from an internal address while the domain publishes an external one).
    if src_addr in domain_addrs:
        logger.info(f"Granting {msg} via forward lookup for signer {msg['signer']!r}.")
        return True

    # Only now is the reverse lookup needed: doing it up front would let its
    # failure deny a request the forward match already justifies.
    rev_name = dns.reversename.from_address(src_addr)  # e.g. 8.8.8.8.in-addr.arpa.
    try:
        src_ptr_names = [ptr.target for ptr in resolver.query(rev_name, "PTR")]
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
    logger.info(
        f"Source check failed: {domain} -> {domain_addrs},"
        f" {src_addr} -> {[str(n) for n in src_ptr_names]}"
    )
    return False


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
        help="JSON file of per-signer static IP-to-domain overrides; a signer it "
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
    if local := [addr for addr in args.dns if _is_local_address(addr)]:
        parser.error(
            f"--dns must not point at this host ({' '.join(local)}): named(8) "
            "blocks while awaiting our decisions, so it can't answer our lookups. "
            "See --detailed-help."
        )

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

    if args.signer_maps:
        with open(args.signer_maps) as f:
            signers = json.load(f)
    else:
        signers = {"certbot": {}}

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
