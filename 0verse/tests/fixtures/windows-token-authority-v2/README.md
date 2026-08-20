# Native LPAC authority-chain interop vector

This additive fixture replaces only the campaign, execution grant, and worker
acceptance from the v1 interop vector. Tests deliberately reuse the byte-exact
v1 scope manifest so campaign-v2 verification proves the same signed scope and
live-host bindings without changing campaign-v1 bytes or expectations.

The corresponding private key is committed test data only and must never be
accepted by a deployed broker.
