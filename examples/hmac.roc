## Tag a message, verify the tag, and derive a key with PBKDF2.
## Run it with: roc examples/hmac.roc
app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.26.0/GddgvsGjiNXrHFW6au5i5dUDbTs8FinQdrgE2Gqmw53t.tar.zst",
	hmac: "../package/main.roc",
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
