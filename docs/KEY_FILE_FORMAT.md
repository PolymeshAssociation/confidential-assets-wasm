# DART key file format, version 1

**Status:** stable. Version 1 is frozen: a change to anything below that alters bytes on disk or
the keys derived from a mnemonic needs a new version.

This document specifies every form in which a Polymesh DART confidential account's keys are
backed up or moved between programs:

1. the **mnemonic**, from which all of a wallet's accounts are derived (section 2);
2. the **raw secret-key hex** of one account (section 3);
3. the **DART key file**: one account's secret keys, encrypted with a password (sections 4 to 8).

The JSON Schema for the key file is
[`schemas/dart-key-file-v1.schema.json`](../schemas/dart-key-file-v1.schema.json). The schema checks
the JSON structure only; a reader that passes the schema MUST still perform the reader procedure
in section 7.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in
RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

## 1. Conventions

- `‖` is byte concatenation. `x[a..b]` is bytes `a` (inclusive) to `b` (exclusive) of `x`.
- `u32le` is a 4-byte unsigned little-endian integer.
- **Hex** means `0x` followed by lowercase hexadecimal digits, two per byte. Writers MUST produce
  exactly this form. The key file's hex fields MUST match it exactly (section 5).
- **base64** means the standard RFC 4648 section 4 alphabet
  `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`, with `=` padding to a
  multiple of 4 characters, no line breaks, and no whitespace. Writers MUST produce this form.
  Readers MUST reject input that contains any other character, lacks the required padding, or
  whose padding bits (the unused low bits of the last data character) aren't zero. This is the
  behaviour of polkadot.js `base64Encode`/`base64Decode` (appendix A).
- The SCALE codec is the Parity SCALE codec. Every SCALE type used here is fixed-size, so its
  encoding is the concatenation of its fields in declaration order, with no length prefixes.
- **Text to bytes.** A string (a mnemonic, a passphrase, a password) is turned into bytes with the
  [WHATWG UTF-8 encoder](https://encoding.spec.whatwg.org/#utf-8-encoder): a JavaScript string's
  lone surrogate (an unpaired U+D800 to U+DFFF code unit) is encoded as U+FFFD (`EF BF BD`), and
  every other code point as UTF-8. This is what `TextEncoder`, wasm-bindgen's string arguments
  and polkadot.js `stringToU8a` do. So the passphrase or password `"\uD800"` is the same as
  `"�"`. A host whose strings can't hold lone surrogates (such as Rust's `String`) is
  unaffected.
- `NFKD(s)` is Unicode Normalization Form KD of `s` (Unicode Standard Annex #15).

## 2. Mnemonic and derivation

This section is frozen forever, for every version: changing anything in it would make existing
users' keys impossible to re-derive. It is implemented by `src/keys.rs` (`generateMnemonic`,
`MasterSeed.fromMnemonic`, `DART_KEY_PATH_TEMPLATE`, `MasterSeed.deriveAccountKeys`), which
delegates to the `bip39` crate 2.2.2 and to DART `polymesh-dart` 1.0.1 (tag `dart-v1.0.1`). The
text below is normative on its own; the crates are the cross-check (appendix A).
`tests/vectors/derivation-v1.json` holds the reference vectors: for each mnemonic, passphrase and
account, the 64-byte `seed` of section 2.1, the public keys, and the complete raw secret key
`secretKeyHex` (section 3), so an implementation can check every intermediate value.

Strings passed in from a host are first encoded as UTF-8 with the WHATWG UTF-8 encoder (section
1), so a lone surrogate becomes U+FFFD.

### 2.1 Mnemonic and seed

1. **Wordlist and length.** A mnemonic is BIP-39 with the English wordlist (2048 lowercase ASCII
   words), of 12, 15, 18, 21 or 24 words. Writers SHOULD generate 24 words, and MUST output the
   words in lowercase, separated by single U+0020 spaces.
2. **Parsing.** A reader parses a mnemonic `phrase` as follows, and MUST reject it if any step
   fails:
   1. Normalise `phrase` to Unicode NFKD.
   2. Split the result on runs of characters with the Unicode `White_Space` property; leading and
      trailing white space is ignored. The pieces are the words.
   3. The number of words MUST be 12, 15, 18, 21 or 24.
   4. Every word MUST exactly equal (byte for byte) a word of the English wordlist. A reader MAY
      lowercase its input before this lookup; that doesn't change the seed, because the seed is
      computed from the wordlist's spelling (item 3 below). This implementation doesn't
      lowercase: it rejects `ABANDON`.
   5. The BIP-39 checksum MUST be valid: with each word's 11-bit wordlist index concatenated
      most significant bit first, the first `32 · n / 3` bits (for `n` words) are the entropy
      `ENT`, and the last `n / 3` bits MUST equal the first `n / 3` bits of `SHA-256(ENT)`.
3. **Seed.** With the canonical words of step 2 (their wordlist spelling) and the passphrase
   (the empty string if none is given):

   ```text
   password = UTF-8(word_1 ‖ " " ‖ word_2 ‖ " " ‖ … ‖ " " ‖ word_n)    (exactly one U+0020 between words)
   salt     = UTF-8("mnemonic" ‖ NFKD(passphrase))
   seed     = PBKDF2-HMAC-SHA512(password, salt, iterations = 2048, dkLen = 64)    (RFC 8018)
   ```

   The passphrase is NFKD-normalised and otherwise used as it is: it is not trimmed, and its case
   is kept.

### 2.2 Secret keys

Account `account`, an integer with `0 ≤ account ≤ 2^31 − 1`, has the path string

```text
path = "m/44'/595'/" ‖ decimal(account) ‖ "'/0/0"
```

where `decimal(account)` is the decimal integer without leading zeros (`0` for zero), and the path
string is ASCII. It is a label: this is not BIP-32 derivation, and nothing else is derived along
the path.

Its two secret keys, `acct.secret` (the account, or signing, key) and `enc.secret` (the
encryption key), are scalars of the Pallas scalar field, the integers modulo the Pallas group
order

```text
r = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
  = 28948022309329048855892746252171976963363056481941647379679742748393362948097    (255 bits)
```

They are computed with KeyGen of
[draft-irtf-cfrg-bls-signature-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-2.3)
section 2.3, with hash `H = SHA-256` (so HKDF is HKDF-SHA-256, RFC 5869), the group order `r`
above, and:

| Input                    | Value                                                        |
|--------------------------|--------------------------------------------------------------|
| `IKM`                    | the 64-byte `seed` of section 2.1                            |
| `salt` for `acct.secret` | the 24 ASCII bytes `POLYMESH-DART-V1-SIG-KEY`                |
| `salt` for `enc.secret`  | the 24 ASCII bytes `POLYMESH-DART-V1-ENC-KEY`                |
| `key_info`               | `u32le(len(path)) ‖ path ‖ u16le(0) ‖ 0x00`                  |
| `L`                      | `ceil((3 · ceil(log2(r))) / 16) = ceil(765 / 16) = 48`       |

In `key_info`, `len(path)` is the path's length in bytes, `u16le(0)` is the two bytes `00 00` (DART's
key-generation counter, a `u16`, always 0 here), and the final `0x00` is the one-byte index of the
first field element DART's `hkdf_to_field` produces (`I2OSP(0, 1)`). For example, account 0 has
`len(path) = 17` and

```text
key_info = 11 00 00 00 ‖ "m/44'/595'/0'/0/0" ‖ 00 00 ‖ 00      (24 bytes)
```

KeyGen is, for each of the two salts:

```text
loop:
    PRK = HKDF-Extract(salt, IKM ‖ 0x00)
    OKM = HKDF-Expand(PRK, key_info ‖ I2OSP(L, 2), L)        (I2OSP(48, 2) = 00 30)
    SK  = OS2IP(OKM) mod r                                   (OKM read as a big-endian integer)
    if SK ≠ 0: return SK
    salt = SHA-256(salt)
```

The first iteration uses the salt as given; it is hashed only if `SK` is 0, which happens with
negligible probability. Both keys use the same `IKM` and `key_info`; only the salt differs.

### 2.3 Public keys

```text
acct.public = acct.secret · sig_key_gen
enc.public  = enc.secret · enc_key_gen
```

is scalar multiplication on the Pallas curve `y² = x³ + 5` over the field of prime
`p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`. The generators are DART's
`dart_gens().sig_key_gen()` and `dart_gens().enc_key_gen()`. Their compressed encodings (section
3.1) are:

```text
sig_key_gen = 0x74535e5be4948ecb1dd353a96d6bd21421f97f037fcde676fa71f1a472fae3a3
enc_key_gen = 0x387134452cc97b763175d92d570f042b6fab62398f25cdcf515119c8e68320a0
```

These two constants are normative, and an implementation MAY hard-code them. They are defined
as:

```text
sig_key_gen = hash_to_pallas(DST = "polymesh-dart-generators", msg = " : sig_key_gen")
enc_key_gen = hash_to_pallas(DST = "polymesh-dart-generators", msg = " : enc_key_gen")
```

(both strings ASCII; each message starts with a space), where `hash_to_pallas` is the RFC 9380
`hash_to_curve` construction (random-oracle encoding: two field elements, each mapped to the
curve, added; Pallas has cofactor 1) with:

- `hash_to_field` using `expand_message_xmd` with SHA-256, `k = 128`, so each field element takes
  `ceil((255 + 128) / 8) = 48` bytes, read big-endian and reduced modulo `p`; **except** that
  `Z_pad` is 48 zero bytes (the per-element length) instead of RFC 9380's 64 (SHA-256's block
  size). This is arkworks `LegacyFieldHasher<Sha256, 128>`, the ark-ff 0.4/0.5 behaviour, so the
  points are not RFC 9380 test-vector compatible;
- `map_to_curve`: the simplified SWU map to the 3-isogenous curve `y² = x³ + A'x + 1265` with
  `Z = −13`, followed by the 3-isogeny to Pallas, with the constants of Zcash `pasta_curves`
  (arkworks `WBMap<PallasConfig>`).

Appendix A gives the source of each constant.

## 3. Raw secret-key hex

The raw secret key of one account is `0x` + the lowercase hex of the SCALE encoding of DART
`AccountKeys` (`AccountKeys.toSecretKeyHex()` in `src/keys.rs`). It is not the mnemonic and not a
seed; it holds the account's key pairs directly.

### 3.1 `AccountKeys` layout (128 bytes)

`AccountKeys { enc: EncryptionKeyPair, acct: AccountKeyPair }`, where each pair is
`{ public, secret }`, encodes as:

| Offset    | Length | Field         | Type                  | Encoding                                         |
|-----------|-------:|---------------|-----------------------|--------------------------------------------------|
| 0         | 32     | `enc.public`  | `EncryptionPublicKey` | compressed Pallas point (arkworks compressed)    |
| 32        | 32     | `enc.secret`  | `EncryptionSecretKey` | Pallas scalar (arkworks compressed, little-endian) |
| 64        | 32     | `acct.public` | `AccountPublicKey`    | compressed Pallas point (arkworks compressed)    |
| 96        | 32     | `acct.secret` | `AccountSecretKey`    | Pallas scalar (arkworks compressed, little-endian) |

The total is exactly **128 bytes**, so the hex form is exactly 258 characters. The 32-byte public
key encodings are the same bytes that `AccountPublicKey.toBytes()` and
`EncryptionPublicKey.toBytes()` return.

A scalar is its integer value below `r`, as 32 bytes little-endian. A point `(x, y)` is `x` (below
`p`) as 32 bytes little-endian, with bit 7 of the last byte set if `y > p − y` (as integers) and
bit 6 set only for the point at infinity, whose only accepted encoding is 31 zero bytes followed
by `0x40`.

Decoders MUST reject input that isn't exactly 128 bytes, and MUST reject a scalar that isn't
below `r`. Readers MAY accept an upper-case `0X` prefix, upper-case digits or a missing prefix in
the raw hex form, as `AccountKeys.fromSecretKeyHex` does; writers MUST NOT produce them.

### 3.2 Consistency of imported secret keys

An `AccountKeys` is **valid** only if all of the following hold. A decoder MUST check them, and
MUST reject the input otherwise:

1. `enc.public` and `acct.public` are valid compressed Pallas points: `x` is below `p`, `x³ + 5`
   is a square modulo `p`, and the flag bits are as described in section 3.1. (Pallas has
   cofactor 1, so every curve point is in the prime-order group.)
2. `enc.secret` and `acct.secret` are non-zero. (Section 2.2 never produces 0.)
3. `acct.public = acct.secret · sig_key_gen` and `enc.public = enc.secret · enc_key_gen`, with the
   generators of section 2.3.

This applies to every import: `AccountKeys.fromSecretKeyHex` rejects such input with
`Invalid secret key: …`, and the key file reader rejects it at step 9 (section 7) as a corrupted
file. Every key derived by section 2 is valid.

## 4. Key file overview

A DART key file is a UTF-8 JSON document holding one account's raw secret key (section 3), encrypted
with a password. Its encryption is byte-compatible with the polkadot.js keyring JSON encoding
version 3 (`jsonEncrypt`/`jsonDecrypt` in `@polkadot/util-crypto` 13.5.9): given the same password
bytes, polkadot.js `jsonDecrypt({ encoded, encoding }, password)` returns the plaintext.

Files SHOULD use the extension `.json` and the media type `application/json`.

Example. `encoded` is elided here (it is always 284 characters); the public keys are the real
ones of account 0 of the `abandon … about` mnemonic with an empty passphrase, the first entry of
`tests/vectors/derivation-v1.json`:

```json
{
  "type": "dart-key-file",
  "version": 1,
  "name": "Treasury",
  "public": {
    "account": "0xb97044f2e52c45bd0b54004a08047f724063d29e7a5aa0b0c699b412662f5326",
    "encryption": "0xdd921243737eaad9594c14748b1c2ee36846294bc7753db187adaefaabf1e327"
  },
  "encoded": "<284 characters of base64>",
  "encoding": {
    "content": ["dart-account-keys", "scale-v1"],
    "type": ["scrypt", "xsalsa20-poly1305"],
    "version": "3"
  },
  "meta": { "created": 1764201600000, "derivationPath": "m/44'/595'/0'/0/0" }
}
```

## 5. JSON structure

The top-level value MUST be a JSON object with exactly the members below. A reader MUST reject a
file with a missing member, a member of the wrong JSON type, or a top-level member not listed here.
Member order is not significant.

The document MUST be valid JSON (RFC 8259) encoded as UTF-8, and in addition:

- **Valid Unicode.** Writers MUST NOT emit a string that isn't valid Unicode, such as one holding
  the escape of a lone surrogate (`"\ud800"`). Readers MAY reject such a string; this
  implementation does (its JSON parser, serde_json, refuses it), reporting an invalid file.
- **Unique member names.** Writers MUST NOT emit an object with two members of the same name.
  Readers SHOULD reject such an object; a reader that doesn't MUST use the last occurrence of
  the name, as JavaScript's `JSON.parse` does. This implementation uses the last occurrence (its
  JSON parser keeps it), so that it reads such a file exactly as a `JSON.parse`-based reader such
  as polkadot.js does.
- **Numbers.** A member whose value is specified as a number equal to an integer accepts any JSON
  number with that value: `1`, `1.0` and `1e0` are the same number, as in JSON Schema. Writers
  SHOULD write integers without a fraction or exponent.

| Member       | Type    | Required | Value                                                                    |
|--------------|---------|----------|--------------------------------------------------------------------------|
| `type`       | string  | yes      | exactly `"dart-key-file"`                                                |
| `version`    | number  | yes      | a JSON number equal to `1` (`1.0` is the same number, as in JSON Schema) |
| `name`       | string  | yes      | a label for the account; MAY be empty                                    |
| `public`     | object  | yes      | section 5.1                                                              |
| `encoded`    | string  | yes      | base64 of the encrypted payload, section 6                               |
| `encoding`   | object  | yes      | section 5.2                                                              |
| `meta`       | object  | yes      | section 5.3                                                              |

### 5.1 `public`

An object with exactly two members, both REQUIRED, each a hex string of exactly 32 bytes
(`^0x[0-9a-f]{64}$`):

- `account`: the account public key, equal to plaintext bytes `[64..96]`;
- `encryption`: the encryption public key, equal to plaintext bytes `[0..32]`.

They let a program show and index the account without the password. A reader MUST reject the file if
they don't match the decrypted plaintext (section 7, step 10). The plaintext's public keys must in
turn match its secret keys (section 3.2, checked at step 9), so a file that opens has `public`
equal to the keys derived from its secrets.

### 5.2 `encoding`

An object with exactly these three members, all REQUIRED:

| Member    | Value                                   | Meaning                                                |
|-----------|-----------------------------------------|--------------------------------------------------------|
| `content` | exactly `["dart-account-keys", "scale-v1"]` | the plaintext is one SCALE-encoded `AccountKeys` (section 3.1) |
| `type`    | exactly `["scrypt", "xsalsa20-poly1305"]`   | scrypt key derivation, then XSalsa20-Poly1305          |
| `version` | exactly the string `"3"`                | polkadot.js keyring JSON encoding version 3            |

Arrays MUST have exactly these elements in exactly this order. A reader MUST reject any other value,
including an `encoding.type` of `["none"]` (an unencrypted polkadot.js payload).

`content` values beginning with `"dart-mnemonic"` are **reserved** for a future multi-account vault
format (for example a wallet extension's encrypted mnemonic). They are invalid in version 1, and a
version 1 reader MUST reject them.

### 5.3 `meta`

An object holding unauthenticated, informational metadata. Neither `meta` nor `name` is covered by
the encryption's authentication tag: anyone can change them without the password, so programs MUST
NOT base security decisions on them.

| Member           | Type    | Required | Value                                                                  |
|------------------|---------|----------|------------------------------------------------------------------------|
| `created`        | number  | yes      | when the file was written, in Unix milliseconds: a JSON number equal to an integer with `0 ≤ created ≤ 2^53 − 1` (`1.0` is the same number as `1`, as in JSON Schema) |
| `derivationPath` | string  | no       | the path the keys were derived at, section 5.3.1                       |

`meta` is **open**: a reader MUST ignore members it doesn't know, and a writer MAY add members
whose names don't collide with ones defined by this or a later version 1 revision. A writer
re-saving a file (for example after a password change) SHOULD preserve members it doesn't know.

#### 5.3.1 `derivationPath`

If present, it MUST have the form `m/44'/595'/{account}'/0/0` from section 2, with `{account}` a
decimal integer from 0 to 2147483647 without leading zeros. A reader MUST reject a file whose
`derivationPath` is present but doesn't have this form, including an out-of-range account such as
`2147483648`. The schema's `derivationPath` pattern encodes exactly this rule, range included, so a
reader that validates against the schema and a reader that follows this text accept the same
files. A writer SHOULD include it when the keys were derived from a mnemonic and it knows the
account index, and MUST omit it otherwise.

It is informational only. A reader MUST NOT use it to derive, check or modify keys; the plaintext
alone determines the keys.

## 6. Encryption

### 6.1 Password

The password is a non-empty string. Its bytes are its UTF-8 encoding by the WHATWG UTF-8 encoder
(section 1: a lone surrogate becomes U+FFFD), with **no** Unicode normalisation. Writers MUST
refuse an empty password.

> **polkadot.js interop:** `jsonEncrypt`, `jsonDecrypt` and `scryptEncode` convert a *string*
> password with `u8aToU8a`, which hex-decodes any string matching `/^0x[0-9a-fA-F]*$/` of even
> length (for example the password `"0x1234"` becomes the two bytes `12 34`). An implementation
> built on polkadot.js MUST therefore pass the password as a `Uint8Array` of its UTF-8 bytes (for
> example `stringToU8a(password)`), never as a string.

### 6.2 Key derivation

```text
DK  = scrypt(P = password bytes, S = salt, N, r, p, dkLen = 64)    (RFC 7914)
key = DK[0..32]
```

`DK[32..64]` is unused. `salt` is 32 bytes.

**Writers** MUST use `N = 131072 (2^17), p = 1, r = 8`, the polkadot.js `DEFAULT_PARAMS`.

**Readers** MUST accept exactly these parameter sets and MUST reject every other `(N, p, r)`
before running scrypt:

| N               | p | r |
|-----------------|---|---|
| 32768 (2^15)    | 3 | 8 |
| 32768 (2^15)    | 1 | 8 |
| 65536 (2^16)    | 2 | 8 |
| 131072 (2^17)   | 1 | 8 |

These are exactly the parameter sets that polkadot.js 13.5.9 `scryptFromU8a` accepts (appendix A):
the `ALLOWED_PARAMS` presets that also pass its safe-limit check (`N ≤ 2^20`, `p ≤ 4`, `r ≤ 16`). The
other two `ALLOWED_PARAMS` presets, `{N: 2^13, p: 10, r: 8}` and `{N: 2^14, p: 5, r: 8}`, fail that
check, so polkadot.js can't decrypt them; they are not valid here either.

### 6.3 Cipher

The cipher is XSalsa20-Poly1305 as defined by NaCl `crypto_secretbox` (identical to libsodium
`crypto_secretbox_easy`), with the 32-byte `key` from section 6.2 and a 24-byte `nonce`:

```text
box = tag[16] ‖ ciphertext[len(plaintext)]
```

where `ciphertext` is the plaintext XORed with the XSalsa20 keystream starting at keystream byte 32
(keystream bytes 0 to 31 are the Poly1305 one-time key), and `tag` is the Poly1305 tag of
`ciphertext`. `box` has no leading zero bytes (it is NaCl's `crypto_secretbox` output with its 16
`BOXZEROBYTES` removed). For a version 1 file, the plaintext is 128 bytes, so `box` is 144 bytes.

### 6.4 `encoded`

```text
payload = salt[32] ‖ N u32le ‖ p u32le ‖ r u32le ‖ nonce[24] ‖ box[144]
encoded = base64(payload)
```

| Offset | Length | Field                               |
|-------:|-------:|-------------------------------------|
| 0      | 32     | `salt`                              |
| 32     | 4      | `N`, u32le                          |
| 36     | 4      | `p`, u32le                          |
| 40     | 4      | `r`, u32le                          |
| 44     | 24     | `nonce`                             |
| 68     | 16     | Poly1305 `tag`                      |
| 84     | 128    | encrypted `AccountKeys`             |

`payload` is exactly **212 bytes**, so `encoded` is exactly **284 characters** and ends in exactly
one `=`. With the default parameters, bytes 32 to 43 are `00 00 02 00 01 00 00 00 08 00 00 00`.

## 7. Reader procedure

A reader MUST perform these steps in order, and MUST reject the file, returning no key material,
when any step fails. It SHOULD report steps 1 to 6 as an invalid or unsupported file, step 8 as a
wrong password or corrupted file, step 9 as a corrupted file, and step 10 as a mismatch between
`public` and the encrypted keys. This implementation reports them as `Invalid key file: …`
(steps 1, 5 and 6), `Unsupported key file` (steps 2, 3, 4 and 7), `Invalid password or corrupted
key file` (step 8), `Corrupted key file: the decrypted keys are invalid` (step 9) and `Key file
public keys don't match its encrypted keys` (step 10).

1. Parse the document as JSON. The top-level value MUST be an object.
2. `type` MUST be `"dart-key-file"`. (A reader SHOULD check this first, to tell a DART key file from
   other JSON, such as a polkadot.js account file.)
3. `version` MUST be a JSON number equal to `1` (`1.0` is the same number, section 5). A reader
   MUST reject any other value, and MUST NOT try to interpret a file of an unknown version.
4. `encoding.version`, `encoding.content` and `encoding.type` MUST have exactly the values in
   section 5.2. A reader MUST reject any other value, and MUST NOT guess.
5. Every other member MUST satisfy section 5: required members present, no unknown top-level,
   `public` or `encoding` members, hex and `meta` values well formed.
6. Decode `encoded` as strict base64 (section 1). The result MUST be exactly 212 bytes.
7. Read `N`, `p` and `r` from bytes 32 to 43. They MUST be one of the parameter sets in section 6.2.
8. Derive `key` (section 6.2) from the password and the salt, then open `box` with `key` and
   `nonce` (section 6.3). Opening MUST fail, and the reader MUST reject the file, if the tag doesn't
   verify.
9. Decode the 128-byte plaintext as a SCALE `AccountKeys` (section 3.1). Decoding MUST consume
   every byte and MUST succeed, and the keys MUST be valid (section 3.2): both public keys valid
   points, both secret keys non-zero, and each public key equal to its secret key times its
   generator. An authenticated plaintext that fails this check is a corrupted file, not a
   mismatch of `public`.
10. Compare plaintext bytes `[64..96]` with `public.account` and bytes `[0..32]` with
    `public.encryption`. Both MUST be equal. With step 9, this proves `public` holds the public
    keys of the file's secret keys.

Readers SHOULD zero the password, `DK`, `key` and the plaintext once they're no longer needed.

## 8. Writer procedure

1. Encode the account's `AccountKeys` as SCALE (section 3.1): 128 bytes.
2. Generate a 32-byte `salt` and a 24-byte `nonce` with a cryptographically secure random number
   generator. A writer MUST generate a fresh salt and nonce for every file it writes, including when
   re-encrypting the same keys.
3. Derive `key` with `N = 2^17, p = 1, r = 8` (section 6.2), encrypt (section 6.3) and build
   `encoded` (section 6.4).
4. Set `public` from the plaintext's public halves, `encoding` to the exact values of section 5.2,
   `type`, `version` and `name`, and `meta.created` to the current time; add `meta.derivationPath`
   when section 5.3.1 says so.
5. Serialise as UTF-8 JSON. Whitespace and member order are not significant.

A writer SHOULD round-trip the file through the reader procedure before telling the user it is
saved.

## 9. Versioning and compatibility

- **Frozen bytes.** For `version: 1`, the payload layout, cipher, key derivation, accepted scrypt
  parameters and plaintext encoding are fixed forever. Section 2's derivation is fixed forever for
  every version.
- **Minor additions** (a revision of this document that keeps `version: 1`) MAY only:
  - define new OPTIONAL `meta` members, which version 1 readers ignore;
  - clarify wording without changing which files are valid.

  They MUST NOT add top-level, `public` or `encoding` members, change the value of any member,
  add an accepted scrypt parameter set, or make a previously valid file invalid.
- **Anything else** requires a new `version` integer, or, for a different plaintext (such as the
  reserved `"dart-mnemonic"` vault), a new `type` value. A reader MUST reject versions and types it
  doesn't implement, so an old reader fails safely on a new file instead of misreading it.
- A writer SHOULD write the lowest version that can express the file, so that older readers can
  read it.

## 10. Migration from earlier formats

The Polymesh confidential-assets UI's version 1 key records (`EncryptedConfidentialKeyRecord`, with
`private.format: "seed-hex"`) can't be converted to this format. Their encrypted data is a seed for
the removed, non-mnemonic derivation, so the keys can't be re-derived from it in the frozen scheme of
section 2. Programs MUST NOT attempt to import them as DART key files. Users of those records must
create new accounts from a mnemonic.

## 11. Test vectors

The reference vectors live in `tests/vectors/key-file-v1.json` (added by the implementation). They
pin, for fixed password bytes, salt, nonce and plaintext, the exact `encoded` string and the complete
key file, so that independent implementations can check their output byte for byte; and they include
files that a reader MUST reject (one per rule in section 7). An implementation MUST pass every vector
in that file. If this document and the vectors disagree, that is a bug to report; neither silently
wins.

## Appendix A. Sources (informative)

Every polkadot.js statement above was checked against `@polkadot/util-crypto` **13.5.9** (with
`@polkadot/util` 13.5.9 and `@scure/base` 1.2.6), and the DART statements against `polymesh-dart`
1.0.1 (git tag `dart-v1.0.1`, commit `022cee3`).

| Statement                                         | Source                                                           |
|---------------------------------------------------|------------------------------------------------------------------|
| Payload = scrypt header ‖ nonce ‖ box             | `json/encrypt.js` lines 9–12                                     |
| `encoding` = `{content, type: ["scrypt","xsalsa20-poly1305"], version: "3"}` | `json/encryptFormat.js` lines 5–11, `json/constants.js` lines 1, 3 |
| Header = salt ‖ N ‖ p ‖ r, each u32le, 44 bytes   | `scrypt/toU8a.js` line 4 (`BN_LE_32_OPTS`), `json/constants.js` line 5 |
| Salt is 32 bytes                                  | `scrypt/encode.js` line 6 (`randomAsU8a()`, default length 32 in `random/asU8a.js` line 17); `scrypt/fromU8a.js` line 12 |
| Nonce is 24 bytes, follows the header             | `nacl/encrypt.js` line 17; `json/constants.js` line 4; `json/decryptData.js` lines 18, 23 |
| scrypt `dkLen = 64`                               | `scrypt/encode.js` line 12 (JS path); the WASM path also returns 64 bytes, and both agree (checked by running both) |
| Cipher key = first 32 bytes of the scrypt output  | `json/encrypt.js` line 10 (`password.subarray(0, 32)`); `json/decryptData.js` line 23 (`u8aFixLength(password, 256, true)` keeps the first 32 bytes) |
| Box = tag[16] ‖ ciphertext                        | `nacl/tweetnacl.js` lines 212–221 (`naclSecretbox` drops the 16 `BOXZEROBYTES`) and 175–183 |
| `DEFAULT_PARAMS = {N: 1<<17, p: 1, r: 8}`         | `scrypt/defaults.js` lines 9–13                                  |
| `ALLOWED_PARAMS`, six presets                     | `scrypt/defaults.js` lines 1–8                                   |
| Safe-limit check rejects `p > 4`                  | `scrypt/fromU8a.js` lines 16–22                                  |
| base64 alphabet, `=` padding, strict decode       | `base64/bs64.js` lines 3–8 (`@scure/base` `base64`, RFC 4648)    |
| String passwords that look like hex are hex-decoded | `@polkadot/util` `u8a/toU8a.js` lines 27–38, `is/hex.js` lines 1, 18–22 |
| `AccountKeys` field order                         | `src/bp/keys.rs` lines 383–386, 112–116, 210–214                 |
| Public keys are 32-byte `CompressedAffine`        | `src/bp/encode.rs` lines 242, 263–265                            |
| Secret keys are 32-byte compressed scalars        | `src/bp/encode.rs` lines 58–100, 401, 405                        |

The derivation of section 2 and the consistency rule of section 3.2 were checked against the crates
this implementation builds with: `bip39` 2.2.2; `polymesh-dart` and `polymesh-dart-bp` 1.0.1
(commit `022cee3`); `polymesh-dart-common` (same commit); the Polymesh `curve-trees` fork at tag
`dart-v1.0.1` (commit `778bb7b`); and the Polymesh `arkworks-algebra` fork at tag `dart-v1.0.1`
(commit `2380877`). The test `vector_secrets_follow_the_spec_keygen_construction` in
`tests/wasm_keys_derivation.rs` recomputes every vector from the text of section 2 with generic
HKDF, PBKDF2 and NFKD implementations, and checks the result against DART.

| Statement                                                  | Source                                                     |
|------------------------------------------------------------|------------------------------------------------------------|
| NFKD of phrase and passphrase                              | `src/keys.rs` `nfkd`, `MasterSeed::from_mnemonic`; `bip39` `src/lib.rs` lines 198–203 |
| Words split on Unicode white space, exact wordlist match   | `bip39` `src/lib.rs` lines 437–451 (`split_whitespace`, `find_word`); `src/language/mod.rs` lines 171–176 (binary search, no case folding) |
| 12, 15, 18, 21 or 24 words                                 | `bip39` `src/lib.rs` lines 682–684                         |
| Checksum: first `n / 3` bits of SHA-256 of the entropy     | `bip39` `src/lib.rs` lines 460–476                         |
| PBKDF2 password = words joined by one space                | `bip39` `src/pbkdf2.rs` lines 20–29                        |
| Salt = `"mnemonic"` ‖ passphrase, 2048 rounds, 64 bytes     | `bip39` `src/pbkdf2.rs` lines 3, 111–112; `src/lib.rs` lines 551–557 |
| The seed is the IKM, as `0x` + hex, decoded back           | `src/keys.rs` `from_seed_bytes`; DART `src/bp/keys.rs` lines 345–357 |
| Path bytes, counter 0, `sig_key_gen`/`enc_key_gen`         | DART `src/bp/keys.rs` lines 360–376                        |
| `key_info` = `u32le(len(path))` ‖ path ‖ counter           | `dart-bp/src/auth_proofs/keys.rs` lines 419–423 (`extend_with_len`), 452–465 (`derive_secret_keys`) |
| The counter is a `u16`, little-endian                      | `dart-common/src/lib.rs` line 11 (`SkGenCounter = u16`); `dart-bp/src/auth_proofs/keys.rs` line 460 |
| Salts `POLYMESH-DART-V1-SIG-KEY`, `POLYMESH-DART-V1-ENC-KEY` | `dart-bp/src/auth_proofs/keys.rs` lines 351, 354         |
| `key_info` ‖ `I2OSP(i, 1)`, `i = 0`; KeyGen with SHA-256   | `dart-bp/src/auth_proofs/keys.rs` lines 362–377 (`hkdf_to_field`) |
| KeyGen loop, `L`, `I2OSP(L, 2)`, `OS2IP mod r`, IKM ≥ 32 bytes | `dart-bp/src/auth_proofs/keys.rs` lines 379–417 (`ietf_keygen`) |
| Pallas group order `r`                                     | `arkworks-algebra` `curves/pallas/src/fields/fr.rs` line 4 |
| Pallas field prime `p`, curve `y² = x³ + 5`, cofactor 1    | `curves/pallas/src/fields/fq.rs` line 4; `curves/pallas/src/curves/mod.rs` lines 34–38 |
| Public key = secret · generator                            | `dart-bp/src/auth_proofs/keys.rs` lines 93–96, 107–110     |
| Generators: `hash_to_pallas("polymesh-dart-generators", " : sig_key_gen")`, `" : enc_key_gen"` | DART `src/bp/mod.rs` lines 263, 288–290, 488–490, 513–519 |
| `hash_to_pallas` = `PallasConfig::hash_to_curve`           | `curve-trees` `bulletproofs/src/hash_to_curve_pasta.rs` lines 8–10 |
| Pallas hashing: `LegacyFieldHasher<Sha256, 128>`, `WBMap`   | `arkworks-algebra` `host-hash-to-curve/src/lib.rs` lines 52–57, 81–84 |
| Legacy `Z_pad` = per-element length (48 bytes)             | `ff/src/fields/field_hashers/mod.rs` lines 103–124, 147–156; `ff/src/fields/field_hashers/expander/mod.rs` lines 102–149 |
| Two field elements, mapped, added, cofactor cleared        | `ec/src/hashing/map_to_curve_hasher.rs` lines 59–76        |
| Isogenous curve `B' = 1265`, `Z = −13`, Zcash isogeny constants | `curves/pallas/src/curves/swu_iso.rs` lines 33–37, 63–64, 83–85 |
| Point compression flags                                    | `ec/src/models/short_weierstrass/serialization_flags.rs` lines 7–14, 22–29, 70–81 |
| A public key decodes only as a valid point; one encoding of infinity | DART `src/bp/encode.rs` lines 336–352                |
