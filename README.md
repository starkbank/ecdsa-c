## A lightweight ECDSA implementation in C

### Overview

This is a C99 implementation of the elliptic curve digital signature algorithm
over secp256k1, used to authenticate requests to the Stark Bank and Stark Infra
APIs. It is the C member of the same family as our Python, Node, PHP, Java,
Ruby, Elixir, .NET, Go and Clojure libraries, and it is tested against the same
fixtures they are.

It exists for the callers the other libraries cannot reach: point-of-sale and
PDV terminals, embedded targets, and desktop software that binds a shared
library rather than a package. The public header is C, so the result is
consumable as a DLL, a shared object or a static archive from anything with a C
FFI.

### Security

The curve arithmetic is not ours. Signing and verification delegate to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1), the Bitcoin Core
implementation, which is constant-time and independently audited. Writing 256
bit modular arithmetic by hand is the single most dangerous thing a library
like this can do, and we do not do it.

Nonces follow hedged RFC 6979: derived deterministically from the key and the
message, with fresh system entropy mixed into the derivation as section 3.6
allows. A repeated message therefore does not repeat the signature, while a
failing system RNG still cannot produce a repeated nonce. If the system RNG is
unavailable, signing fails rather than falling back to something weaker.

SHA-256 and base64 are vendored, at around two hundred lines of fixed-width
integer work with no secret-dependent branching, checked against the NIST CAVP
and RFC 4648 vectors. That keeps the library at one link-time dependency.

### Installation

libsecp256k1 is the only dependency.

```bash
brew install secp256k1          # macOS
apt-get install libsecp256k1-dev # Debian and Ubuntu
```

Then:

```bash
make                # libstarkecdsa.a
make shared         # libstarkecdsa.dylib, or libstarkecdsa.so.1 on Linux
make test           # build and run the suite
```

Point the build at a libsecp256k1 in a non-standard place with
`make SECP256K1_PREFIX=/path/to/prefix`.

### Curves

secp256k1 only, which is the curve the Stark APIs use.

### Sample code

```c
#include <stdio.h>
#include <string.h>
#include "starkecdsa.h"

int main(void)
{
    const char *pem =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK\n"
        "oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB\n"
        "RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==\n"
        "-----END EC PRIVATE KEY-----\n";
    const char *message = "{\"transfer\":{\"amount\":100}}";

    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_signature *signature = NULL;
    char *header = NULL;

    if (starkecdsa_private_key_from_pem(pem, &privateKey) != STARKECDSA_OK) {
        return 1;
    }
    if (starkecdsa_sign((const unsigned char *)message, strlen(message), privateKey, &signature) != STARKECDSA_OK) {
        return 1;
    }

    /* This is what the Digital-Signature request header carries. */
    starkecdsa_signature_to_base64(signature, 0, &header);
    printf("Digital-Signature: %s\n", header);

    starkecdsa_private_key_public_key(privateKey, &publicKey);
    printf("verifies: %s\n",
           starkecdsa_verify((const unsigned char *)message, strlen(message), signature, publicKey) == STARKECDSA_OK
               ? "yes" : "no");

    starkecdsa_free(header);
    starkecdsa_signature_free(signature);
    starkecdsa_public_key_free(publicKey);
    starkecdsa_private_key_free(privateKey);
    return 0;
}
```

Every function returns `STARKECDSA_OK` or a negative code that
`starkecdsa_strerror` describes. Every buffer the library hands back is
released with `starkecdsa_free`, and never with the caller's own `free`: on
Windows the two can belong to different C runtimes.

### Binding from another language

The header is deliberately plain. It declares no `long`, no `bool`, no inline
functions and no structs that cross the boundary, so the types are the same
width under LP64 and LLP64 and every object is an opaque pointer. A shared
build exports only the thirty `starkecdsa_*` entry points; everything else,
including libsecp256k1, stays hidden, so two Stark libraries in one process
cannot collide.

### OpenSSL

Keys and signatures interoperate with OpenSSL, and the test suite proves it
against a signature OpenSSL produced:

```bash
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

Note that a private key file written this way begins with an `EC PARAMETERS`
block before the key itself, which this library skips.

### Run unit tests

```bash
make test
```
