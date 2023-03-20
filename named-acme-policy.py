#!/usr/bin/env python3
"""
This is an external named(8) update-policy decider daemon that allows dynamic
DNS update requests if they are part of an Automatic Certificate Management
Environment (ACME) DNS-01 challenge, for example, as used by Let's Encrypt's
certbot client. This daemon implements a more secure permissions model than the
bult-in named(8) mechanisms allow.

For instructions on how to integrate this daemon with named(8) see
https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy
Basically this comes down to having something like the following in a zone
configuration file:
    ...
    update-policy {
        grant "local:/path/to/socket" external *; 
    ...
(the '*' is there just to satisfy the config parser: replacing it with any other
string wouldn't change anything.

IMPORTANT: Named(8) evaluates externally-decided policies synchronously
(even name lookups will be blocked). Therefore we must be as quick as possible.
"""
import argparse
import dns.resolver
import logging
import pickle
import shutil
import socket
import struct
import sys
from pathlib import Path


def unpack_req_msg(data):
    """Convert a dynamic DNS request message into a dictionary.

    For the request message format, see the "external" rule type documentation:
    https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy
    Request packets look like this:
    (b'\x00\x00\x00\x01\x00\x00\x00bcertbot\x00_acme-challenge.bookstack.i'
      b'cecube.wisc.edu\x00144.92.100.35\x00TXT\x00certbot/165/7089\x00\x00'
      b'\x00\x00\x00'),
    which unpacks to:
    (1, 98, 'certbot', '_acme-challenge.bookstack.icecube.wisc.edu',
      '144.92.100.35', 'TXT', 'certbot/165/7089', 0, '')
    """
    signer, rr_name, src_addr, rr_type = data[8:].split(b"\x00")[0:4]
    return {
        "signer": signer.decode(),
        "src_addr": src_addr.decode(),
        "rr_name": rr_name.decode(),
        "rr_type": rr_type.decode(),
    }


def is_valid_acme_update(msg, signer, resolver):
    """Check if the message appears to be a valid ACME DNS-01 request,
    and passes some security checks.
    """
    subdomain, domain = msg["rr_name"].split(".", 1)
    if subdomain != "_acme-challenge" or msg["rr_type"] != "TXT":
        logging.info(f"{msg} doesn't look related to an ACME challenge")
        return False
    if msg["signer"] != signer:
        logging.info(f"Request {msg} wasn't signed by {signer}")
        return False
    if msg["src_addr"] not in [str(a) for a in resolver.query(domain, "A")]:
        logging.info(f"Request {msg} did not originate from {domain}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="This is an external named(8) update-policy decider "
        "daemon that allows dynamic DNS update requests if they are part "
        "of an Automatic Certificate Management Environment (ACME) DNS-01 "
        "challenge, for example as used by Let's Encrypt's certbot client. "
        "This daemon implements a more secure permissions model than the "
        "bult-in named(8) mechanisms allow.",
        epilog="Notes: (A) For instructions on how to integrate this daemon "
        "with named(8) see [1]. (B) Because externally-decided update-policy "
        "statements are executed synchronously, for request origin security "
        "check, this script needs to use a DNS server other than the one it's "
        "running on (to avoid deadlock). "
        "[1] https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--socket",
        metavar="SOCKET_PATH",
        required=True,
        help="path to the Unix socket file for communication with named(8)",
    )
    parser.add_argument(
        "--signer",
        metavar="NAME",
        default="certbot",
        help="TSIG key identifier permitted to issue ACME requests",
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
        default=["8.8.8.8", "4.4.4.4"],
        help="different nameserver for address verification; see note (B)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log_file,
        level=logging.INFO,
        format="%(asctime)-23s %(levelname)s %(message)s",
    )
    if args.log_file:
        logging.getLogger().addHandler(logging.StreamHandler())

    # External update-policy decision protocol is this:
    #   1. Named(8) writes a dynamic DNS update request message to the socket.
    #   2. The external decider process writes 1 or 0 to the socket.
    #   3. Named(8) reads the socket and grants or denies the request.
    # Named(8) evaluates externally-decided policies synchronously (even name
    # lookups will be blocked). Therefore we must be as quick as possible.

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = args.dns
    resolver.timeout = 0.2  # seconds to wait for a response from a server
    resolver.lifetime = 0.5  # seconds to spend trying to get an answer
    try:
        resolver.query("google.com", "A")
    except Exception as e:
        parser.exit(1, f"--dns servers failed test: {e}\n")

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
        conn, addr = server.accept()
        data = conn.recv(2**20)
        logging.info(f"Received request {data}")
        try:
            msg = unpack_req_msg(data)
        except Exception as e:
            logging.error(f"Denying request {data} because of decoding failure {e}")
            conn.send(struct.pack("!I", 0))
            continue
        else:
            if is_valid_acme_update(msg, args.signer, resolver):
                logging.info(f"Granting request {msg}")
                conn.send(struct.pack("!I", 1))
            else:
                logging.info(f"Denying request {msg}")
                conn.send(struct.pack("!I", 0))
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
