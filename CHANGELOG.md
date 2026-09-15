# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to the following versioning pattern:

Given a version number MAJOR.MINOR.PATCH, increment:

- MAJOR version when **breaking changes** are introduced;
- MINOR version when **backwards compatible changes** are introduced;
- PATCH version when backwards compatible bug **fixes** are implemented.


## [Unreleased]

## [0.1.0] - 2026-09-15
### Added
- ECDSA sign and verify over secp256k1, hedged RFC 6979 nonces, low-s signatures
- Private and public keys from and to PEM, DER, hex and compressed hex
- Signatures from and to DER and base64, with the optional recovery byte
- C99 sources behind a C89-compatible public header, static and shared builds
- Shared build exports only the public entry points, enforced at link time
- One randomized libsecp256k1 context, created once and shared between threads
- Strict SEC1 and SubjectPublicKeyInfo readers: curve OID and public point required, trailing bytes rejected
- Canonical base64 only; private key material wiped through starkecdsa_free_secret
- Continuous integration on Linux and macOS with sanitizers and valgrind
