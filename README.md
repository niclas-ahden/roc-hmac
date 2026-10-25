# roc-hmac

HMAC-SHA-256 and PBKDF2-HMAC-SHA-256 in pure Roc, built on the compiler's
native `Crypto.SHA256`. It follows RFC 2104 and RFC 8018 and is tested against
the official test vectors.

See the documentation at [https://niclas-ahden.github.io/roc-hmac/](https://niclas-ahden.github.io/roc-hmac/).

## Usage

```roc
app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.26.0/GddgvsGjiNXrHFW6au5i5dUDbTs8FinQdrgE2Gqmw53t.tar.zst",
	hmac: "https://github.com/niclas-ahden/roc-hmac/releases/download/0.3.1/C4tVVXqXphwD9P271wA9BE62KikS63ZhTjWtqbkDQWMs.tar.zst",
}

import pf.Stdout
import hmac.Hmac

main! = |_args| {
	key = "a very secret key".to_utf8()
	message = "our message".to_utf8()

	# Create a 32-byte HMAC-SHA-256 tag
	tag = Hmac.sha256({ key, message })

	# Now let's verify the tag. Pretend we got some bytes
	# from somewhere:
	some_bytes = tag.to_bytes()

	# Construct a `Hmac` from the bytes and then safely compare using `==`.
	# This one is `True`, since we're comparing the tag with itself:
	valid = tag == Hmac.from_bytes(some_bytes)

	# `Hmac` implements a safe `==` which is not vulnerable to timing attacks.
	# `Hmac.verify_sha256` does the same, but takes bytes directly.

	# Now let's do some PBKDF2

	# `Hmac.iterations` ensures that the given iterations value is non-zero:
	Ok(iterations) = Hmac.iterations(4096)

	# You may have noticed that we were able to just unwrap the
	# `Ok(iterations)` here without any kind of error handling... How?
	#
	# Roc's compiler is really nice and looks at the literal at compile-time
	# and since it's a positive number, it says "this can't possibly
	# be an error". Now our HMAC can be completely infallible!
	#
	# Note that Roc can only do this _before_ any effectful calls.
	# So if you want to do this, just do it early and carry the
	# `iterations` value with you. Of course you could also just handle
	# the error case as usual (e.g. if you're passing in a value that's only
	# known at runtime).

	# Now PBKDF2-HMAC-SHA-256 key derivation is infallible
	derived = Hmac.pbkdf2_sha256({
		password: "correct horse battery staple".to_utf8(),
		salt: "per-user random salt".to_utf8(),
		iterations,
		length: 32,
	})

	Stdout.line!("Valid: ${Str.inspect(valid)}")?
	Stdout.line!("Derived key: ${Str.inspect(derived)}")?

	Ok({})
}
```

## Security

### Compare `Hmac`s, not bytes

When dealing with HMACs you must protect yourself against timing attacks. If you
compare two HMAC values as bytes against each other like so:

```roc
some_hmac_bytes == some_other_hmac_bytes
```

The `==` will short-circuit as soon as one byte differs, and that tiny timing
difference is enough for an attacker to forge a tag byte by byte.

`roc-hmac` protects you from this by implementing a custom `==` for `Hmac` which
is safe from timing attacks:

```roc
# This is safe
Hmac.sha256({ key, message }) == Hmac.from_bytes(some_bytes)

# This is _not_ safe
Hmac.sha256({ key, message }).to_bytes() == some_bytes
```

It protects you in two ways:

1. It looks at every byte. Differences are OR-ed together and checked once at
   the end, so there's no early exit.
2. It MACs both sides again before comparing (a well-known protection named the
   "double HMAC" trick), under a key hashed from both tags. So even if the
   comparison _did_ leak timing, the attacker would learn prefixes of a MAC
   under a key they can't know, rather than of the tag itself.

Since we can't prove that we run in constant time, we use the double-HMAC
trick so that we don't have to: even a fully leaky comparison gives an attacker
nothing useful.

### What about the rest?

HMAC and PBKDF2 over SHA-256 don't branch on secret bytes and don't index into
tables with them, and the hashing itself happens in the native builtin. What
you _can_ observe from the outside is input lengths (a key longer than 64
bytes gets hashed first, per the RFCs), but every HMAC implementation reveals
that.

Roc values are immutable and reference counted, so there's no way to zero a
key from memory after use. That's the same deal as HMAC in any
garbage-collected language.

This package also stops at hash-based constructions on purpose. Primitives
like AES and RSA have secret-dependent memory access patterns which should
be handled in your Roc platform.
