# Trust Registry Contract

Minimal Compact contract package for the Midnight trust registry.

Current scope:

- registry initialization
- bootstrap maintainer registration
- generic maintainer-signed action authorization
- threshold validation for later multi-maintainer governance work

This slice intentionally stops short of issuer, verifier, recognition, and
epoch-anchor flows. Those surfaces stack on top of this package.
