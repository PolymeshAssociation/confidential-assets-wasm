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

## 2. Mnemonic and derivation

These constants are the ones implemented by `src/keys.rs` (`generateMnemonic`,
`MasterSeed.fromMnemonic`, `DART_KEY_PATH_TEMPLATE`, `MasterSeed.deriveAccountKeys`). They are
frozen forever: changing any of them would make existing users' keys impossible to re-derive.
`tests/vectors/derivation-v1.json` holds the reference vectors.

1. **Mnemonic:** BIP-39 with the English wordlist, 12, 15, 18, 21 or 24 words. Writers SHOULD
   generate 24 words. Implementations MUST verify the BIP-39 checksum and MUST reject words outside
   the English wordlist.
2. **Seed:** the BIP-39 seed: both the mnemonic and the optional passphrase are NFKD-normalised, then
   `seed = PBKDF2-HMAC-SHA512(password = mnemonic, salt = "mnemonic" ‖ passphrase, iterations = 2048,
   dkLen = 64)`. The passphrase defaults to the empty string.
3. **Master seed:** the DART `MasterSeed` is created with the 64-byte BIP-39 seed as its input key
   material (IKM). (`src/keys.rs` passes it to DART `MasterSeed::from_seed` as `0x` + its hex, which
   DART hex-decodes back to the same 64 bytes.)
4. **Account path:** account `account` is derived with DART `MasterSeed::derive_account_keys` at the
   path string `m/44'/595'/{account}'/0/0`, where `{account}` is the decimal integer `account`
   without leading zeros and `0 ≤ account ≤ 2^31 − 1`. The path string's ASCII bytes are DART's
   derivation input; it is not BIP-32 derivation. The DART crate version this was frozen against is
   `polymesh-dart` 1.0.1 (tag `dart-v1.0.1`).

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

Decoders MUST reject input that isn't exactly 128 bytes, and MUST reject a point or scalar that
DART's decoder rejects (for example, a scalar not below the Pallas group order). Readers MAY accept
an upper-case `0X` prefix, upper-case digits or a missing prefix in the raw hex form, as
`AccountKeys.fromSecretKeyHex` does; writers MUST NOT produce them.

### 3.2 Consistency of imported secret keys

A decoder can't yet check that `enc.secret` and `acct.secret` correspond to `enc.public` and
`acct.public`: DART doesn't expose a public helper to recompute a public key from a secret key.
Until it does, an imported raw secret key, or the plaintext of a key file, is trusted to be
internally consistent. Implementations SHOULD add this check once DART provides the helper. The key
file's public-key check (section 7, step 10) compares the file's `public` member with the public
halves of the plaintext; it does not prove the secrets match.

## 4. Key file overview

A DART key file is a UTF-8 JSON document holding one account's raw secret key (section 3), encrypted
with a password. Its encryption is byte-compatible with the polkadot.js keyring JSON encoding
version 3 (`jsonEncrypt`/`jsonDecrypt` in `@polkadot/util-crypto` 13.5.9): given the same password
bytes, polkadot.js `jsonDecrypt({ encoded, encoding }, password)` returns the plaintext.

Files SHOULD use the extension `.json` and the media type `application/json`.

Example (values abbreviated; `encoded` is always 284 characters):

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

| Member       | Type    | Required | Value                                                                    |
|--------------|---------|----------|--------------------------------------------------------------------------|
| `type`       | string  | yes      | exactly `"dart-key-file"`                                                |
| `version`    | number  | yes      | exactly the integer `1`                                                  |
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
they don't match the decrypted plaintext (section 7, step 10).

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
| `created`        | integer | yes      | when the file was written, in Unix milliseconds, `0 ≤ created ≤ 2^53 − 1` |
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

The password is a non-empty Unicode string. Its bytes are its UTF-8 encoding, with **no** Unicode
normalisation. Writers MUST refuse an empty password.

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
wrong password or corrupted file, and steps 9 and 10 as a corrupted file.

1. Parse the document as JSON. The top-level value MUST be an object.
2. `type` MUST be `"dart-key-file"`. (A reader SHOULD check this first, to tell a DART key file from
   other JSON, such as a polkadot.js account file.)
3. `version` MUST be the integer `1`. A reader MUST reject any other value, and MUST NOT try to
   interpret a file of an unknown version.
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
   every byte and MUST succeed.
10. Compare plaintext bytes `[64..96]` with `public.account` and bytes `[0..32]` with
    `public.encryption`. Both MUST be equal. (This doesn't prove that the secrets match the public
    keys; see section 3.2.)

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
