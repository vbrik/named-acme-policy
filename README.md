In a nutshell, this project allows to securely configure ISC bind for
automatic certificate issuing using ACME DNS-01 challenge
(for example https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

This is an external named(8) update-policy decider daemon that allows dynamic
DNS (RFC 2136) update requests if they are part of an Automatic Certificate
Management Environment (ACME) DNS-01 challenge, for example, as used by Let's
Encrypt's [certbot client](https://certbot-dns-rfc2136.readthedocs.io/en/stable/).
This daemon implements a *somewhat* more secure permissions model than the built-in
named(8) mechanisms allow for automated certificate issuance using DNS-01 challenge
via RFC 2136.

The daemon allows dynamic DNS updates if they meet the following criteria:
* Name of the DNS resource record being updated starts with `_acme-challenge.`.
* The update request has been signed by a TSIG key/identity configured via `--signer-maps`.
* Either: (1) the domain name of the challenge (the part after `_acme-challenge.`)
resolves to the IP address from which the update request originated,
OR (2) the request's source address resolves to the domain name of the
challenge (this is for multi-homed cases, where the request comes from an internal
address but the domain resolves to the external address),
OR (3) the request's source address maps to the requested domain (or to `*`,
meaning any domain) for that signer in the `--signer-maps` file.

`--signer-maps` is a JSON file of per-signer static IP-to-domain overrides, e.g.:
```json
{
  "certbot": {"144.92.100.35": ["dtn-2.icecube.wisc.edu"]},
  "k8s-certbot": {"10.1.2.3": "*", "10.1.2.4": "*"}
}
```
Each IP maps to either a list of domains or the literal `"*"` (not a bare
domain string), meaning any domain — useful for e.g. letting Kubernetes
workers request certs for arbitrary ingress hostnames under a dedicated key.
A `"*"` entry grants blanket `_acme-challenge` write access in every zone
whose update-policy uses this daemon's socket, so keep it out of zones it
shouldn't touch.

For instructions on how to integrate this daemon with named(8) see
https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-update-policy

Basically this comes down to having something like the following in a zone
configuration file:
```
    ...
    update-policy {
        grant "local:/path/to/socket" external *; 
    ...
```
(the '*' is there just to satisfy the config parser and is unrelated to the
`--signer-maps` wildcard above: replacing it with any other string wouldn't change
anything.)

## Testing

Unit tests cover request parsing and the update-approval logic. Run them with:
```
pip install -r requirements.txt pytest
pytest
```
