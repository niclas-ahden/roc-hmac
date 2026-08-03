## Tag a message, verify the tag, and derive a key with PBKDF2.
## Run it with: roc examples/hmac.roc
app [main!] {
	pf: platform "https://github.com/niclas-ahden/basic-cli/releases/download/0.23.0/7NpDhuqoqGFedmVLvmm1zjq37GCmaFGzwr5sz4ch9wTK.tar.zst",
	hmac: "../package/main.roc",
}

import pf.Stdout
import hmac.Hmac

main! = |_args| {
	# The compiler evaluates iterations(4096) while type-checking, proves it
	# is Ok, and accepts the bare destructure, so a zero literal here would
	# be a compile error. The proof only covers code above the first
	# effectful call, hence the destructure comes first in the function.
	Ok(iterations) = Hmac.iterations(4096)

	key = "a very secret key".to_utf8()
	message = "the message to authenticate".to_utf8()

	tag = Hmac.sha256({ key, message })
	Stdout.line!("tag: ${to_hex(tag)}")?

	# Verify with Hmac.verify_sha256, never with a plain equality: it compares
	# without short-circuiting and through the double-HMAC pattern, so it is
	# safe against timing attacks.
	valid = Hmac.verify_sha256({ key, message, tag })
	tampered = Hmac.verify_sha256({ key, message, tag: tag.drop_first(1) })
	Stdout.line!("genuine tag verifies: ${Str.inspect(valid)}, tampered tag verifies: ${Str.inspect(tampered)}")?

	# pbkdf2_sha256 cannot fail: the checked iterations value is proof of a
	# positive count
	derived = Hmac.pbkdf2_sha256({
		password: "correct horse battery staple".to_utf8(),
		salt: "per-user random salt".to_utf8(),
		iterations,
		length: 32,
	})
	Stdout.line!("derived key: ${to_hex(derived)}")?

	Ok({})
}

to_hex : List(U8) -> Str
to_hex = |bytes|
	bytes.fold(
		"",
		|acc, byte| "${acc}${nibble_to_hex(byte.shr_zf_wrap(4))}${nibble_to_hex(byte.bitwise_and(15))}",
	)

nibble_to_hex : U8 -> Str
nibble_to_hex = |n| {
	c = if n < 10 {
		n + '0'
	} else {
		n - 10 + 'a'
	}
	match Str.from_utf8([c]) {
		Ok(s) => s
		Err(_) => ""
	}
}
