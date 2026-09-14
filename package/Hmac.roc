import nz.NonZero

## HMAC-SHA-256 and PBKDF2-HMAC-SHA-256 (RFC 2104, RFC 8018) in pure Roc on
## top of the built-in `Crypto.SHA256`.
##
## ```
## tag = Hmac.sha256({ key: secret, message: payload })
## ok = tag == Hmac.from_bytes(received)
## Ok(iterations) = Hmac.iterations(4096)
## derived = Hmac.pbkdf2_sha256({ password, salt, iterations, length: 32 })
## ```
##
## Timing attacks: the hashing itself runs in the native SHA-256 builtin,
## which has no data-dependent branches or lookups, and this module never
## branches on secret byte values. A computed tag is an `Hmac` value rather
## than raw bytes, and `==` on tags is the timing-safe comparison, so the
## obvious way to check a tag is the safe one. Compare tags, never the bytes
## `to_bytes` hands back: `==` on those short-circuits.
Hmac :: { bytes : List(U8) }.{

	## The HMAC-SHA-256 of `message` under `key`, as an [Hmac] tag.
	## A key longer than the 64-byte SHA-256 block is hashed first, per RFC 2104.
	sha256 : { key : List(U8), message : List(U8) } -> Hmac
	sha256 = |{ key, message }| {
		padded = prepare_key(key)
		Hmac.{ bytes: hmac_padded(xor_each(padded, 0x36), xor_each(padded, 0x5c), message) }
	}

	## A received tag, wrapped for comparison against a computed one.
	## Wrong-length bytes are accepted here and fail the comparison.
	from_bytes : List(U8) -> Hmac
	from_bytes = |bytes| Hmac.{ bytes }

	## The raw tag bytes, for sending a computed tag onward.
	to_bytes : Hmac -> List(U8)
	to_bytes = |tag| tag.bytes

	## Whether two tags hold the same bytes. This is what `==` runs.
	##
	## Safe against timing attacks by construction: both sides are MACed
	## under a key hashed from both tags before comparing, so any timing
	## signal reveals prefixes of a MAC under a key the attacker cannot
	## know, and turning that into a forgery would require inverting
	## SHA-256. The comparison also inspects every byte with no early
	## exit.
	is_eq : Hmac, Hmac -> Bool
	is_eq = |a, b| {
		padded = prepare_key(Crypto.SHA256.hash(a.bytes.concat(b.bytes)).to_bytes())
		ipad_key = xor_each(padded, 0x36)
		opad_key = xor_each(padded, 0x5c)
		eq_every_byte(
			hmac_padded(ipad_key, opad_key, a.bytes),
			hmac_padded(ipad_key, opad_key, b.bytes),
		)
	}

	## Whether `tag` is the HMAC-SHA-256 of `message` under `key`. A tag of the
	## wrong length is never valid.
	##
	## This is `Hmac.sha256({ key, message }) == Hmac.from_bytes(tag)`,
	## here as one call for the common case of checking received tag bytes.
	verify_sha256 : { key : List(U8), message : List(U8), tag : List(U8) } -> Bool
	verify_sha256 = |{ key, message, tag }|
		Hmac.sha256({ key, message }) == Hmac.from_bytes(tag)

	## A PBKDF2 iteration count checked to be positive: `Ok` wrapping the
	## checked count, or `Err(Zero)`. RFC 8018 requires at least 1.
	##
	## With a literal count the compiler proves the check while type-checking,
	## so a bare `Ok(iterations) = Hmac.iterations(4096)` destructure compiles,
	## and `Hmac.iterations(0)` in that position is a compile error. A count
	## only known at runtime is checked once with a `match`, where it enters.
	iterations : U64 -> Try(NonZero(U64), [Zero])
	iterations = |count| NonZero.new(count)

	## The PBKDF2-HMAC-SHA-256 of `password`, as `length` derived bytes.
	## A `length` of 0 derives an empty key.
	##
	## The iteration count comes from [Hmac.iterations], so an invalid count
	## is unrepresentable here and this function cannot fail. The count is a
	## cost factor: each iteration is two SHA-256 compressions, so e.g.
	## SCRAM's usual 4096 costs about 8k native hash calls. For deriving keys
	## and running SCRAM that is milliseconds. As a server-side password
	## store at OWASP-scale iteration counts, measure before committing.
	pbkdf2_sha256 : { password : List(U8), salt : List(U8), iterations : NonZero(U64), length : U64 } -> List(U8)
	pbkdf2_sha256 = |{ password, salt, iterations: count, length }| {
		padded = prepare_key(password)
		ipad_key = xor_each(padded, 0x36)
		opad_key = xor_each(padded, 0x5c)
		derive_blocks(ipad_key, opad_key, salt, count.get(), length, 1, [])
	}
}

block_size = 64

## Hash an over-long key, then zero-pad to the block size.
prepare_key : List(U8) -> List(U8)
prepare_key = |key| {
	shortened =
		if key.len() > block_size {
			Crypto.SHA256.hash(key).to_bytes()
		} else {
			key
		}
	shortened.concat(List.repeat(0, block_size - shortened.len()))
}

xor_each : List(U8), U8 -> List(U8)
xor_each = |bytes, pad| bytes.map(|b| b.bitwise_xor(pad))

## HMAC core over already-padded-and-XORed keys, so PBKDF2 pays the key setup
## once rather than per iteration.
hmac_padded : List(U8), List(U8), List(U8) -> List(U8)
hmac_padded = |ipad_key, opad_key, message| {
	inner = Crypto.SHA256.hash(ipad_key.concat(message)).to_bytes()
	Crypto.SHA256.hash(opad_key.concat(inner)).to_bytes()
}

## One PBKDF2 block per recursion, until enough bytes are derived.
derive_blocks : List(U8), List(U8), List(U8), U64, U64, U32, List(U8) -> List(U8)
derive_blocks = |ipad_key, opad_key, salt, iterations, length, index, acc|
	if acc.len() >= length {
		acc.take_first(length)
	} else {
		u1 = hmac_padded(ipad_key, opad_key, salt.concat(u32_be(index)))
		block = iterate_block(ipad_key, opad_key, u1, u1, iterations - 1)
		derive_blocks(ipad_key, opad_key, salt, iterations, length, index + 1, acc.concat(block))
	}

## U_2..U_c, XOR-folded into the block.
iterate_block : List(U8), List(U8), List(U8), List(U8), U64 -> List(U8)
iterate_block = |ipad_key, opad_key, prev_u, acc, remaining|
	if remaining == 0 {
		acc
	} else {
		u = hmac_padded(ipad_key, opad_key, prev_u)
		iterate_block(ipad_key, opad_key, u, xor_bytes(acc, u), remaining - 1)
	}

xor_bytes : List(U8), List(U8) -> List(U8)
xor_bytes = |a, b| xor_bytes_help(a, b, 0, [])

xor_bytes_help = |a, b, index, acc|
	match a.get(index) {
		Err(_) => acc
		Ok(x) => xor_bytes_help(a, b, index + 1, acc.append(x.bitwise_xor(b.get(index).ok_or(0))))
	}

## PBKDF2's INT(i): the block index as four big-endian bytes.
u32_be : U32 -> List(U8)
u32_be = |value|
	[
		value.shr_zf_wrap(24).to_u8_wrap(),
		value.shr_zf_wrap(16).to_u8_wrap(),
		value.shr_zf_wrap(8).to_u8_wrap(),
		value.to_u8_wrap(),
	]

## Equality that inspects every byte: differences are OR-accumulated and
## checked once at the end, so a mismatch never exits early.
eq_every_byte : List(U8), List(U8) -> Bool
eq_every_byte = |a, b|
	if a.len() != b.len() {
		Bool.False
	} else {
		diff_every_byte(a, b, 0, 0) == 0
	}

diff_every_byte : List(U8), List(U8), U64, U8 -> U8
diff_every_byte = |a, b, index, acc|
	match a.get(index) {
		Err(_) => acc
		Ok(x) => diff_every_byte(a, b, index + 1, acc.bitwise_or(x.bitwise_xor(b.get(index).ok_or(0))))
	}

# ---- Test helpers ----

## Decode lowercase hex, for the test vectors below.
from_hex : Str -> List(U8)
from_hex = |text| from_hex_help(text.to_utf8(), [])

from_hex_help = |chars, acc|
	match chars.get(0) {
		Err(_) => acc
		Ok(hi) =>
			match chars.get(1) {
				Err(_) => acc
				Ok(lo) => from_hex_help(chars.drop_first(2), acc.append(nibble(hi).shl_wrap(4).bitwise_or(nibble(lo))))
			}
		}

nibble : U8 -> U8
nibble = |c| if c >= '0' and c <= '9' {
	c - '0'
} else {
	c - 'a' + 10
}

expect from_hex("00ff10") == [0, 255, 16]

# ---- HMAC-SHA-256 test vectors, RFC 4231 ----

# Test case 1
expect
	Hmac.sha256({ key: List.repeat(0x0b, 20), message: "Hi There".to_utf8() })
		== Hmac.from_bytes(from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))

# Test case 2: a key shorter than the block size
expect
	Hmac.sha256({ key: "Jefe".to_utf8(), message: "what do ya want for nothing?".to_utf8() })
		== Hmac.from_bytes(from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))

# Test case 3
expect
	Hmac.sha256({ key: List.repeat(0xaa, 20), message: List.repeat(0xdd, 50) })
		== Hmac.from_bytes(from_hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"))

# Test case 4
expect
	Hmac.sha256({ key: from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), message: List.repeat(0xcd, 50) })
		== Hmac.from_bytes(from_hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"))

# Test case 5 is omitted: it truncates the tag to 128 bits, and verify_sha256 rejects wrong-length tags by design (covered below)

# A key of exactly the block size is used as-is, the boundary of prepare_key
expect
	Hmac.sha256({ key: List.repeat(0xaa, 64), message: "Test Using Block-Size Key".to_utf8() })
		== Hmac.from_bytes(from_hex("d0d577cd64caf12b90eaf0053fb42f18132bf30903a0bf6a1187dbd38bbc6e07"))

# Test case 6: a key larger than the block size is hashed first
expect
	Hmac.sha256({ key: List.repeat(0xaa, 131), message: "Test Using Larger Than Block-Size Key - Hash Key First".to_utf8() })
		== Hmac.from_bytes(from_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))

# Test case 7: key and data both larger than the block size
expect
	Hmac.sha256({ key: List.repeat(0xaa, 131), message: "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_utf8() })
		== Hmac.from_bytes(from_hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"))

# ---- Tag values and their equality ----

# to_bytes returns what from_bytes wrapped
expect Hmac.from_bytes(from_hex("00ff10")).to_bytes() == [0, 255, 16]

# == is true exactly when the bytes match
expect Hmac.from_bytes([1, 2, 3]) == Hmac.from_bytes([1, 2, 3])
expect (Hmac.from_bytes([1, 2, 3]) == Hmac.from_bytes([1, 2, 4])) == Bool.False
expect (Hmac.from_bytes([1, 2, 3]) == Hmac.from_bytes([1, 2])) == Bool.False
expect Hmac.from_bytes([]) == Hmac.from_bytes([])

# ---- verify_sha256 ----

expect
	Hmac.verify_sha256({
		key: "Jefe".to_utf8(),
		message: "what do ya want for nothing?".to_utf8(),
		tag: from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
	})

# One flipped bit fails
expect
	Hmac.verify_sha256({
		key: "Jefe".to_utf8(),
		message: "what do ya want for nothing?".to_utf8(),
		tag: from_hex("5adcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
	})
		== Bool.False

# A truncated tag fails
expect
	Hmac.verify_sha256({
		key: "Jefe".to_utf8(),
		message: "what do ya want for nothing?".to_utf8(),
		tag: from_hex("5bdcc146bf60754e6a042426089575c7"),
	})
		== Bool.False

# The wrong key fails
expect
	Hmac.verify_sha256({
		key: "JefeJefe".to_utf8(),
		message: "what do ya want for nothing?".to_utf8(),
		tag: from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
	})
		== Bool.False

# ---- PBKDF2-HMAC-SHA-256 test vectors ----
#
# No RFC gives PBKDF2-HMAC-SHA-256 vectors for RFC 6070's inputs, so the
# "password"/"salt" cases below are that set recomputed over SHA-256, as
# circulated in draft-josefsson-pbkdf2-test-vectors and checked against
# OpenSSL. The "passwd"/"salt" case is RFC 7914 section 11's first vector.

# A match rather than a bare Ok(...) destructure: a top-level destructure in
# a package module panics roc test in the current compiler
iterations_from : U64 -> NonZero(U64)
iterations_from = |count|
	match Hmac.iterations(count) {
		Ok(checked) => checked
		Err(Zero) => {
			crash "test iteration counts are positive"
		}
	}

iterations_1 = iterations_from(1)

iterations_2 = iterations_from(2)

iterations_4096 = iterations_from(4096)

expect
	Hmac.pbkdf2_sha256({ password: "password".to_utf8(), salt: "salt".to_utf8(), iterations: iterations_1, length: 32 })
		== from_hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")

expect
	Hmac.pbkdf2_sha256({ password: "password".to_utf8(), salt: "salt".to_utf8(), iterations: iterations_2, length: 32 })
		== from_hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")

expect
	Hmac.pbkdf2_sha256({ password: "password".to_utf8(), salt: "salt".to_utf8(), iterations: iterations_4096, length: 32 })
		== from_hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")

# Multi-block output (length > 32) with block-sized inputs
expect
	Hmac.pbkdf2_sha256({
		password: "passwordPASSWORDpassword".to_utf8(),
		salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".to_utf8(),
		iterations: iterations_4096,
		length: 40,
	})
		== from_hex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")

# RFC 7914 section 11: two whole blocks, nothing truncated
expect
	Hmac.pbkdf2_sha256({ password: "passwd".to_utf8(), salt: "salt".to_utf8(), iterations: iterations_1, length: 64 })
		== from_hex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")

# A short length truncates the first block
expect
	Hmac.pbkdf2_sha256({ password: "password".to_utf8(), salt: "salt".to_utf8(), iterations: iterations_1, length: 16 })
		== from_hex("120fb6cffcf8b32c43e7225256c4f837")

# A length of 0 derives an empty key
expect
	Hmac.pbkdf2_sha256({ password: "password".to_utf8(), salt: "salt".to_utf8(), iterations: iterations_1, length: 0 })
		== []

# Zero iterations is invalid, RFC 8018 requires a positive count
expect
	match Hmac.iterations(0) {
		Err(Zero) => Bool.True
		Ok(_) => Bool.False
	}
