This is an external named(8) update-policy decider daemon that allows dynamic
DNS update requests if they are part of an Automatic Certificate Management
Environment (ACME) DNS-01 challenge, for example, as used by Let's Encrypt
certbot client. This daemon implements a more secure permissions model than the
bult-in named(8) mechanisms allow.

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
