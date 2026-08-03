# roc-hmac

HMAC-SHA-256 and PBKDF2-HMAC-SHA-256 (RFC 2104, RFC 8018) in pure Roc, built
on the compiler's native `Crypto.SHA256`.

See the documentation at [https://niclas-ahden.github.io/roc-hmac/](https://niclas-ahden.github.io/roc-hmac/).

## Usage

```roc
app [main!] {
	pf: platform "https://github.com/niclas-ahden/basic-cli/releases/download/0.23.0/7NpDhuqoqGFedmVLvmm1zjq37GCmaFGzwr5sz4ch9wTK.tar.zst",
    hmac: "<latest roc-hmac release bundle URL>",
}

import pf.Stdout
import hmac.Hmac

main! = |_args| {
    # A positive literal count is proven Ok while the compiler
    # type-checks, so this bare destructure compiles, and iterations(0)
    # in its place would be a compile error. The proof only covers code
    # above the first effectful call, so check literals at the top.
    Ok(iterations) = Hmac.iterations(4096)

    key = "a very secret key".to_utf8()
    message = "the message to authenticate".to_utf8()

    # A 32-byte HMAC-SHA-256 tag
    tag = Hmac.sha256({ key, message })

    # Verify with verify_sha256, never with a plain equality (see Security)
    valid = Hmac.verify_sha256({ key, message, tag })
    Stdout.line!("tag verifies: ${Str.inspect(valid)}")?

    # PBKDF2-HMAC-SHA-256 key derivation, infallible because the checked
    # iterations value proves a positive count
    derived = Hmac.pbkdf2_sha256({
        password: "correct horse battery staple".to_utf8(),
        salt: "per-user random salt".to_utf8(),
        iterations,
        length: 32,
    })
    Stdout.line!("derived key: ${Str.inspect(derived)}")?

    Ok({})
}
```

An iteration count that only arrives at runtime (a config file, a SCRAM
server-first-message) is checked once with a `match`, where it enters:

```roc
iterations = match Hmac.iterations(count_from_config) {
    Ok(checked) => checked
    Err(Zero) => # reject the configuration
}
```

These are the primitives SCRAM-SHA-256 needs (together with base64, see
[roc-base64](https://github.com/niclas-ahden/roc-base64)), and they are useful
on their own for API request signing, webhook signatures, cookie authentication,
and key derivation.

## Security

**Verification.** `verify_sha256` is written to be safe against timing attacks,
and using it (rather than `==` on tags) is the one rule this package asks of
you. A plain equality short-circuits at the first differing byte, and against a
verifier that checks attacker-supplied tags that timing difference famously
allows forging a tag byte by byte. `verify_sha256` defends in two layers:

1. It compares with no early exit: differences across all bytes are
   OR-accumulated and checked once at the end.
2. It compares re-MACed values (the double-HMAC pattern): both sides are MACed
   again under a key derived from the expected tag before comparing. Even if
   the comparison leaked, it would leak prefixes of `HMAC(expected, tag)`, and
   turning that into a valid tag would require inverting SHA-256.

The second layer matters because Roc is interpreted and true constant-time
execution cannot be proven at that level. The double-HMAC pattern removes the
need to prove it: a leak reveals nothing a forger can use. This is the standard
remedy in runtimes without a native constant-time comparison.

**Computation.** HMAC and PBKDF2 over SHA-256 have no secret-dependent branches
or secret-indexed table lookups, and the hashing itself runs in the native
builtin. What remains observable is input *lengths* (a key longer than 64 bytes
is hashed first, per the RFCs), which HMAC reveals in every implementation.

**Caveats.** Roc values are immutable and reference counted, so keys and
passwords cannot be zeroed from memory after use, the same property as HMAC
implementations in other garbage-collected languages. And this package
deliberately stops at hash-based constructions: primitives such as AES or RSA
have secret-dependent memory access patterns and do not belong in a high-level
language, keep those in a platform.

**PBKDF2 cost.** Each iteration is two native SHA-256 calls behind an
interpreted loop. SCRAM's usual 4096 iterations take milliseconds. If you plan
to verify passwords server-side at OWASP-scale iteration counts (hundreds of
thousands), measure first. RFC 8018 requires a positive count, so
`pbkdf2_sha256` takes a checked count from `Hmac.iterations` (a `NonZero(U64)`
from [roc-non-zero](https://github.com/niclas-ahden/roc-non-zero)) rather than
a bare integer, an invalid count is unrepresentable, and `pbkdf2_sha256`
itself cannot fail. A `length` of 0 derives an empty key.

## Development

The flake provides the Roc compiler:

```sh
nix develop
roc check package/main.roc
roc test package/main.roc
```

The test suite is the RFC 4231 HMAC-SHA-256 vectors and the RFC 7914
PBKDF2-HMAC-SHA-256 vectors, plus verification tests.
