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

This slice intentionally still stops short of epoch-anchor flows and
multi-maintainer threshold execution. Those surfaces stack on top of this
package.
