In a nutshell, this project allows to securely configure ISC bind for
automatic certificate issuing using ACME DNS-01 challenge
(for example https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

This is an external named(8) update-policy decider daemon that allows dynamic
DNS (RFC 2136) update requests if they are part of an Automatic Certificate
Management Environment (ACME) DNS-01 challenge, for example, as used by Let's
Encrypt's [certbot client](https://certbot-dns-rfc2136.readthedocs.io/en/stable/).
This daemon implements a more secure permissions model than the bult-in named(8)
mechanisms allow for automated certificate issuance using DNS-01 challenge via
RFC 2136.

The daemon allows dynamic DNS update if they meet the following criteria:
* Name of the resource record being updates starts with `_acme-challenge.`.
* The update request has been signed by a specific TSIG key.
* The domain name of the challenge (the part after `_acme-challenge.`)
  resolves to the IP address from which the update requests originated.

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
(the '*' is there just to satisfy the config parser: replacing it with any other
string wouldn't change anything.)
