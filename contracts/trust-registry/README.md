# Trust Registry Contract

Minimal Compact contract package for the Midnight trust registry.

Current scope:

- registry initialization
- bootstrap maintainer registration
- generic maintainer-signed action authorization
- threshold validation for later multi-maintainer governance work
- issuer authorization lifecycle and scope queries
- verifier authorization lifecycle and scope queries
- recognition lifecycle and scope queries
- epoch-anchor publication and current/by-id lookup

This slice intentionally still stops short of multi-maintainer threshold
execution above `1-of-N`, historical lookup by timestamp, and client-facing
query adapters. Those surfaces stack on top of this package.
