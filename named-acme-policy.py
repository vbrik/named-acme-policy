#!/usr/bin/env python3
"""External update-policy decider daemon for named(8): grants dynamic DNS
updates that belong to an ACME DNS-01 challenge, such as certbot's.

DETAILED_HELP below is the user-facing documentation (named(8) setup, security
model). Keep operator-facing explanation there rather than duplicating it here.
"""

import argparse
import json
import logging
import shutil
import socket
import struct
import sys
from pathlib import Path

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


SECURITY MODEL

  A request is granted only when all of the following hold:

    * the resource record name starts with "_acme-challenge." and its type is TXT;

    * the request is signed by a signer present in --signer-maps (a request from
      an unlisted signer is always denied);

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
  signer any domain from that address. Such an entry confers blanket
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

    allowed = maps.get(msg["src_addr"], [])
    if allowed == "*" or (isinstance(allowed, list) and domain in allowed):
        logger.info(f"Granting {msg} via static map for signer {msg['signer']!r}.")
        return True

    # No static override, so make the requestor prove it owns the domain: either
    # the domain resolves to the source address (1-to-1 and round-robin hosts), or
    # the source address reverse-resolves to the domain (multi-homed hosts, which
    # send from an internal address while the domain publishes an external one).
    try:
        domain_addrs = [str(a) for a in resolver.query(domain, "A")]
    except dns.resolver.NoAnswer:
        logger.error(f"Failed to resolve {domain}.")
        return False
    try:
        rev_name = dns.reversename.from_address(
            msg["src_addr"]
        )  # e.g. 8.8.8.8.in-addr.arpa
        src_ptr_names = [str(a) for a in resolver.query(rev_name, "PTR")]
    except dns.resolver.NoAnswer:
        logger.warning(f"Reverse DNS lookup failed for {msg['src_addr']}.")
        src_ptr_names = []
    if msg["src_addr"] not in domain_addrs and domain + "." not in src_ptr_names:
        logger.info(
            f"Request {msg} failed to pass source security check:"
            f" {domain} doesn't resolve to {msg['src_addr']}"
            f" and {msg['src_addr']} doesn't resolve to {domain}"
        )
        return False
    logger.info(
        f"Granting {msg} via source-address verification for signer {msg['signer']!r}."
    )
    return True


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
        nargs="+",
        default=["8.8.8.8", "8.8.4.4"],
        help="resolver(s) used to verify request source addresses; must not be "
        "the named(8) this daemon serves, which would deadlock "
        "(default: 8.8.8.8 8.8.4.4)",
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
