//! The encrypted DART key file, version 1.
//!
//! `docs/KEY_FILE_FORMAT.md` is the normative specification and
//! `schemas/dart-key-file-v1.schema.json` its JSON Schema. The encryption is byte-compatible with
//! the polkadot.js keyring JSON encoding version 3 (`jsonEncrypt`/`jsonDecrypt`).
//!
//! The format logic (layout, parsing, validation, the reader procedure) is plain Rust and returns
//! [`KeyFileError`]; only `encryptKeyFile`, `decryptKeyFile` and `DecryptedKeyFile` at the end of
//! the file are exported to JavaScript.

use base64::Engine as _;
use codec::{DecodeAll, Encode};
use crypto_secretbox::aead::{AeadInPlace, KeyInit};
use crypto_secretbox::{Key, Nonce, Tag, XSalsa20Poly1305};
use polymesh_dart::AccountKeys as NativeAccountKeys;
use rand::RngCore as _;
use serde::Serialize;
use serde_json::{Map, Value};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::keys::check_key_consistency;
use crate::AccountKeys;

const FILE_TYPE: &str = "dart-key-file";
const FILE_VERSION: u64 = 1;
const ENCODING_CONTENT: [&str; 2] = ["dart-account-keys", "scale-v1"];
const ENCODING_TYPE: [&str; 2] = ["scrypt", "xsalsa20-poly1305"];
const ENCODING_VERSION: &str = "3";

/// The top-level members (section 5).
const MEMBERS: [&str; 7] = [
    "type", "version", "name", "public", "encoded", "encoding", "meta",
];

const PLAINTEXT_LEN: usize = 128;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// `salt ‖ N ‖ p ‖ r`.
const HEADER_LEN: usize = SALT_LEN + 12;
/// `salt ‖ N ‖ p ‖ r ‖ nonce ‖ tag ‖ ciphertext`: 212 bytes (section 6.4).
const PAYLOAD_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN + PLAINTEXT_LEN;
const NONCE_AT: usize = HEADER_LEN;
const TAG_AT: usize = NONCE_AT + NONCE_LEN;
const CIPHERTEXT_AT: usize = TAG_AT + TAG_LEN;

/// scrypt output length; the cipher key is its first 32 bytes.
const SCRYPT_DK_LEN: usize = 64;

/// The largest `meta.created`, `2^53 − 1`.
const MAX_CREATED: u64 = (1 << 53) - 1;

const PATH_PREFIX: &str = "m/44'/595'/";
const PATH_SUFFIX: &str = "'/0/0";
const MAX_ACCOUNT: u64 = (1 << 31) - 1;

/// scrypt cost parameters, as stored in the payload header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScryptParams {
    pub n: u32,
    pub p: u32,
    pub r: u32,
}

/// The parameters every writer uses: polkadot.js `DEFAULT_PARAMS` (section 6.2).
pub(crate) const WRITE_PARAMS: ScryptParams = ScryptParams {
    n: 1 << 17,
    p: 1,
    r: 8,
};

/// The only parameter sets a reader accepts (section 6.2).
pub(crate) const ACCEPTED_PARAMS: [ScryptParams; 4] = [
    ScryptParams {
        n: 1 << 15,
        p: 3,
        r: 8,
    },
    ScryptParams {
        n: 1 << 15,
        p: 1,
        r: 8,
    },
    ScryptParams {
        n: 1 << 16,
        p: 2,
        r: 8,
    },
    ScryptParams {
        n: 1 << 17,
        p: 1,
        r: 8,
    },
];

/// Why reading or writing a key file failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyFileError {
    /// Malformed: not JSON, or a member is missing, unknown or ill-formed (steps 1, 5 and 6).
    Invalid(String),
    /// An unknown type, version or encoding, or scrypt parameters outside the accepted list
    /// (steps 2, 3, 4 and 7).
    Unsupported,
    /// The tag didn't verify: a wrong password or a modified payload (step 8). Deliberately
    /// doesn't say which.
    InvalidPasswordOrCorrupted,
    /// The plaintext isn't a valid, internally consistent `AccountKeys` (step 9).
    Corrupted,
    /// `public` doesn't match the decrypted keys (step 10).
    PublicKeyMismatch,
    /// The writer refused its input.
    Write(String),
}

impl KeyFileError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Invalid(detail) => format!("Invalid key file: {}", detail),
            Self::Unsupported => "Unsupported key file".to_string(),
            Self::InvalidPasswordOrCorrupted => {
                "Invalid password or corrupted key file".to_string()
            }
            Self::Corrupted => "Corrupted key file: the decrypted keys are invalid".to_string(),
            Self::PublicKeyMismatch => {
                "Key file public keys don't match its encrypted keys".to_string()
            }
            Self::Write(detail) => detail.clone(),
        }
    }
}

impl From<KeyFileError> for JsValue {
    fn from(e: KeyFileError) -> JsValue {
        JsValue::from_str(&e.message())
    }
}

fn invalid(detail: impl Into<String>) -> KeyFileError {
    KeyFileError::Invalid(detail.into())
}

// ---------------------------------------------------------------------------------------------
// Encryption (section 6)
// ---------------------------------------------------------------------------------------------

/// `scrypt(password, salt, N, r, p, dkLen = 64)` (section 6.2).
fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: ScryptParams,
) -> Result<Zeroizing<[u8; SCRYPT_DK_LEN]>, KeyFileError> {
    // Never run scrypt with parameters outside the accepted list (each N is a power of two).
    if !ACCEPTED_PARAMS.contains(&params) {
        return Err(KeyFileError::Unsupported);
    }
    let log_n = params.n.trailing_zeros() as u8;
    let scrypt_params = scrypt::Params::new(log_n, params.r, params.p, SCRYPT_DK_LEN)
        .map_err(|_| KeyFileError::Unsupported)?;
    let mut dk = Zeroizing::new([0u8; SCRYPT_DK_LEN]);
    scrypt::scrypt(password, salt, &scrypt_params, &mut dk[..])
        .map_err(|_| KeyFileError::Unsupported)?;
    Ok(dk)
}

/// `bytes[at..at + N]` as an array. Every caller passes a range inside a fixed-size array, so
/// `err` is never returned in practice.
fn array_at<const N: usize>(
    bytes: &[u8],
    at: usize,
    err: KeyFileError,
) -> Result<&[u8; N], KeyFileError> {
    bytes
        .get(at..at + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(err)
}

/// XSalsa20-Poly1305 keyed with `DK[0..32]` (section 6.2).
fn cipher_for(
    dk: &[u8; SCRYPT_DK_LEN],
    err: KeyFileError,
) -> Result<XSalsa20Poly1305, KeyFileError> {
    Ok(XSalsa20Poly1305::new(<&Key>::from(array_at::<32>(
        dk, 0, err,
    )?)))
}

/// Encrypts `plaintext` and returns the 212-byte payload (sections 6.2 to 6.4).
pub(crate) fn seal(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    params: ScryptParams,
    plaintext: &[u8; PLAINTEXT_LEN],
) -> Result<[u8; PAYLOAD_LEN], KeyFileError> {
    let dk = derive_key(password, salt, params)?;
    let cipher = cipher_for(
        &dk,
        KeyFileError::Write("Key file encryption failed".to_string()),
    )?;

    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..SALT_LEN].copy_from_slice(salt);
    payload[32..36].copy_from_slice(&params.n.to_le_bytes());
    payload[36..40].copy_from_slice(&params.p.to_le_bytes());
    payload[40..44].copy_from_slice(&params.r.to_le_bytes());
    payload[NONCE_AT..TAG_AT].copy_from_slice(nonce);
    payload[CIPHERTEXT_AT..].copy_from_slice(plaintext);
    let tag = match cipher.encrypt_in_place_detached(
        <&Nonce>::from(nonce),
        &[],
        &mut payload[CIPHERTEXT_AT..],
    ) {
        Ok(tag) => tag,
        Err(_) => {
            // The buffer may still hold plaintext.
            payload.zeroize();
            return Err(KeyFileError::Write(
                "Key file encryption failed".to_string(),
            ));
        }
    };
    payload[TAG_AT..CIPHERTEXT_AT].copy_from_slice(&tag);
    Ok(payload)
}

/// Reads and checks the scrypt parameters in a payload header (step 7).
fn payload_params(payload: &[u8; PAYLOAD_LEN]) -> Result<ScryptParams, KeyFileError> {
    let u32le = |at: usize| {
        u32::from_le_bytes([
            payload[at],
            payload[at + 1],
            payload[at + 2],
            payload[at + 3],
        ])
    };
    let params = ScryptParams {
        n: u32le(32),
        p: u32le(36),
        r: u32le(40),
    };
    if ACCEPTED_PARAMS.contains(&params) {
        Ok(params)
    } else {
        Err(KeyFileError::Unsupported)
    }
}

/// Decrypts a payload whose parameters `payload_params` accepted (step 8).
fn open(
    password: &[u8],
    payload: &[u8; PAYLOAD_LEN],
    params: ScryptParams,
) -> Result<Zeroizing<[u8; PLAINTEXT_LEN]>, KeyFileError> {
    let dk = derive_key(password, &payload[..SALT_LEN], params)?;
    let cipher = cipher_for(&dk, KeyFileError::InvalidPasswordOrCorrupted)?;
    let nonce = array_at::<NONCE_LEN>(payload, NONCE_AT, KeyFileError::InvalidPasswordOrCorrupted)?;
    let tag = array_at::<TAG_LEN>(payload, TAG_AT, KeyFileError::InvalidPasswordOrCorrupted)?;
    let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
    plaintext.copy_from_slice(&payload[CIPHERTEXT_AT..]);
    cipher
        .decrypt_in_place_detached(
            <&Nonce>::from(nonce),
            &[],
            &mut plaintext[..],
            <&Tag>::from(tag),
        )
        .map_err(|_| KeyFileError::InvalidPasswordOrCorrupted)?;
    Ok(plaintext)
}

// ---------------------------------------------------------------------------------------------
// JSON (sections 5 and 7)
// ---------------------------------------------------------------------------------------------

/// The fields of a key file other than `type`, `version` and `encoding`, which are constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyFileFields {
    pub name: String,
    pub public_account: [u8; 32],
    pub public_encryption: [u8; 32],
    pub payload: [u8; PAYLOAD_LEN],
    pub created: u64,
    pub derivation_path: Option<String>,
}

#[derive(Serialize)]
struct FileOut<'a> {
    #[serde(rename = "type")]
    file_type: &'static str,
    version: u64,
    name: &'a str,
    public: PublicOut,
    encoded: String,
    encoding: EncodingOut,
    meta: MetaOut<'a>,
}

#[derive(Serialize)]
struct PublicOut {
    account: String,
    encryption: String,
}

#[derive(Serialize)]
struct EncodingOut {
    content: [&'static str; 2],
    #[serde(rename = "type")]
    encoding_type: [&'static str; 2],
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetaOut<'a> {
    created: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    derivation_path: Option<&'a str>,
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn base64_engine() -> base64::engine::GeneralPurpose {
    // Standard alphabet, `=` padding required on decode, non-zero padding bits rejected.
    base64::engine::general_purpose::STANDARD
}

/// Serialises a key file (section 8, steps 4 and 5).
pub(crate) fn to_json(fields: &KeyFileFields) -> Result<String, KeyFileError> {
    let file = FileOut {
        file_type: FILE_TYPE,
        version: FILE_VERSION,
        name: &fields.name,
        public: PublicOut {
            account: hex0x(&fields.public_account),
            encryption: hex0x(&fields.public_encryption),
        },
        encoded: base64_engine().encode(fields.payload),
        encoding: EncodingOut {
            content: ENCODING_CONTENT,
            encoding_type: ENCODING_TYPE,
            version: ENCODING_VERSION,
        },
        meta: MetaOut {
            created: fields.created,
            derivation_path: fields.derivation_path.as_deref(),
        },
    };
    serde_json::to_string_pretty(&file)
        .map_err(|e| KeyFileError::Write(format!("Failed to serialise the key file: {}", e)))
}

/// Whether `path` is `m/44'/595'/{account}'/0/0` with `{account}` from 0 to 2^31 − 1, without
/// leading zeros (section 5.3.1).
pub(crate) fn is_valid_derivation_path(path: &str) -> bool {
    let Some(account) = path
        .strip_prefix(PATH_PREFIX)
        .and_then(|rest| rest.strip_suffix(PATH_SUFFIX))
    else {
        return false;
    };
    !account.is_empty()
        && account.len() <= 10
        && account.bytes().all(|b| b.is_ascii_digit())
        && (account == "0" || !account.starts_with('0'))
        && account.parse::<u64>().map_or(false, |n| n <= MAX_ACCOUNT)
}

/// A JSON number that is an integer in `0..=max`. As in JSON Schema, a number with a zero
/// fractional part (`1.0`) is an integer.
fn as_integer(value: &Value, max: u64) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return (n <= max).then_some(n);
    }
    let f = value.as_f64()?;
    (f >= 0.0 && f.fract() == 0.0 && f <= max as f64).then_some(f as u64)
}

fn is_string_array(value: Option<&Value>, expected: &[&str]) -> bool {
    match value.and_then(Value::as_array) {
        Some(items) => {
            items.len() == expected.len()
                && items
                    .iter()
                    .zip(expected)
                    .all(|(item, e)| item.as_str() == Some(e))
        }
        None => false,
    }
}

/// `^0x[0-9a-f]{64}$`.
fn parse_hex32(value: Option<&Value>, member: &str) -> Result<[u8; 32], KeyFileError> {
    let bad = || {
        invalid(format!(
            "`{}` must be 0x and 64 lower-case hex digits",
            member
        ))
    };
    let s = value.and_then(Value::as_str).ok_or_else(bad)?;
    let digits = s.strip_prefix("0x").ok_or_else(bad)?;
    if digits.len() != 64
        || !digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(digits, &mut out).map_err(|_| bad())?;
    Ok(out)
}

fn object<'a>(
    value: Option<&'a Value>,
    member: &str,
) -> Result<&'a Map<String, Value>, KeyFileError> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(format!("`{}` must be an object", member)))
}

fn only_members(
    map: &Map<String, Value>,
    allowed: &[&str],
    within: &str,
) -> Result<(), KeyFileError> {
    match map.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(unknown) => Err(invalid(format!("unknown member `{}{}`", within, unknown))),
        None => Ok(()),
    }
}

/// Reader procedure steps 1 to 7: everything that doesn't need the password.
pub(crate) fn parse(json: &str) -> Result<KeyFileFields, KeyFileError> {
    // 1. A JSON object.
    let value: Value = serde_json::from_str(json).map_err(|_| invalid("not JSON"))?;
    let file = value
        .as_object()
        .ok_or_else(|| invalid("the top-level value must be an object"))?;

    // 2. The type.
    if file.get("type").and_then(Value::as_str) != Some(FILE_TYPE) {
        return Err(KeyFileError::Unsupported);
    }

    // 3. The version: a JSON number equal to 1 (`1.0` is the same number).
    if file.get("version").and_then(|v| as_integer(v, u64::MAX)) != Some(FILE_VERSION) {
        return Err(KeyFileError::Unsupported);
    }

    // 4. The encoding's values.
    let encoding = file.get("encoding").and_then(Value::as_object);
    let supported = encoding.map_or(false, |e| {
        e.get("version").and_then(Value::as_str) == Some(ENCODING_VERSION)
            && is_string_array(e.get("content"), &ENCODING_CONTENT)
            && is_string_array(e.get("type"), &ENCODING_TYPE)
    });
    let Some(encoding) = encoding.filter(|_| supported) else {
        return Err(KeyFileError::Unsupported);
    };

    // 5. Every other member.
    for member in MEMBERS {
        if !file.contains_key(member) {
            return Err(invalid(format!("missing member `{}`", member)));
        }
    }
    only_members(file, &MEMBERS, "")?;
    only_members(encoding, &["content", "type", "version"], "encoding.")?;

    let name = file
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`name` must be a string"))?
        .to_string();

    let public = object(file.get("public"), "public")?;
    only_members(public, &["account", "encryption"], "public.")?;
    let public_account = parse_hex32(public.get("account"), "public.account")?;
    let public_encryption = parse_hex32(public.get("encryption"), "public.encryption")?;

    let meta = object(file.get("meta"), "meta")?;
    let created = meta
        .get("created")
        .and_then(|v| as_integer(v, MAX_CREATED))
        .ok_or_else(|| invalid("`meta.created` must be an integer from 0 to 2^53 - 1"))?;
    let derivation_path = match meta.get("derivationPath") {
        None => None,
        Some(path) => match path.as_str() {
            Some(path) if is_valid_derivation_path(path) => Some(path.to_string()),
            _ => {
                return Err(invalid(
                    "`meta.derivationPath` must be m/44'/595'/{account}'/0/0 with an account \
                     from 0 to 2147483647",
                ))
            }
        },
    };

    let encoded = file
        .get("encoded")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`encoded` must be a string"))?;

    // 6. Strict base64 of exactly 212 bytes.
    let bytes = base64_engine()
        .decode(encoded)
        .map_err(|_| invalid("`encoded` is not valid base64"))?;
    let payload: [u8; PAYLOAD_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid(format!("`encoded` must be {} bytes", PAYLOAD_LEN)))?;

    // 7. The scrypt parameters.
    payload_params(&payload)?;

    Ok(KeyFileFields {
        name,
        public_account,
        public_encryption,
        payload,
        created,
        derivation_path,
    })
}

/// The whole reader procedure (section 7).
pub(crate) fn decrypt(
    json: &str,
    password: &[u8],
) -> Result<(KeyFileFields, NativeAccountKeys), KeyFileError> {
    // 1 to 7.
    let fields = parse(json)?;
    let params = payload_params(&fields.payload)?;
    // 8.
    let plaintext = open(password, &fields.payload, params)?;
    // 9. A valid `AccountKeys` whose public keys are its secret keys times DART's generators.
    // (`keys` is zeroized on drop if the check fails.)
    let mut keys =
        NativeAccountKeys::decode_all(&mut &plaintext[..]).map_err(|_| KeyFileError::Corrupted)?;
    check_key_consistency(&keys).map_err(|_| KeyFileError::Corrupted)?;
    // 10.
    if plaintext[64..96] != fields.public_account || plaintext[0..32] != fields.public_encryption {
        keys.zeroize();
        return Err(KeyFileError::PublicKeyMismatch);
    }
    Ok((fields, keys))
}

/// The writer procedure (section 8) with a caller-chosen salt, nonce and time. Not exported to
/// JavaScript: a writer must use a fresh random salt and nonce for every file.
pub(crate) fn encrypt_with(
    keys: &NativeAccountKeys,
    password: &[u8],
    name: &str,
    derivation_path: Option<&str>,
    created: u64,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<String, KeyFileError> {
    if password.is_empty() {
        return Err(KeyFileError::Write(
            "The key file password must not be empty".to_string(),
        ));
    }
    if let Some(path) = derivation_path {
        if !is_valid_derivation_path(path) {
            return Err(KeyFileError::Write(format!(
                "Invalid derivation path {:?}: must be m/44'/595'/{{account}}'/0/0 with an account \
                 from 0 to 2147483647",
                path
            )));
        }
    }
    if created > MAX_CREATED {
        return Err(KeyFileError::Write(
            "The creation time is out of range".to_string(),
        ));
    }

    let encoded = Zeroizing::new(keys.encode());
    let plaintext: Zeroizing<[u8; PLAINTEXT_LEN]> = Zeroizing::new(
        encoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyFileError::Write("Unexpected account keys encoding".to_string()))?,
    );
    let payload = seal(password, salt, nonce, WRITE_PARAMS, &plaintext)?;

    let mut public_account = [0u8; 32];
    public_account.copy_from_slice(&plaintext[64..96]);
    let mut public_encryption = [0u8; 32];
    public_encryption.copy_from_slice(&plaintext[0..32]);
    to_json(&KeyFileFields {
        name: name.to_string(),
        public_account,
        public_encryption,
        payload,
        created,
        derivation_path: derivation_path.map(str::to_string),
    })
}

// ---------------------------------------------------------------------------------------------
// JavaScript API
// ---------------------------------------------------------------------------------------------

/// Encrypts an account's keys into a DART key file (`docs/KEY_FILE_FORMAT.md`), with a password.
///
/// The keys are protected with scrypt (N = 2^17, r = 8, p = 1) and XSalsa20-Poly1305, the
/// encryption of polkadot.js keyring JSON files. Every call uses a fresh random salt and nonce.
/// It takes about a second and 128 MiB of memory.
///
/// `name` and `derivationPath` are stored in clear and aren't authenticated: anyone can change
/// them without the password.
///
/// # Arguments
/// * `keys` - The account keys to protect.
/// * `password` - A non-empty password. Its UTF-8 bytes are used as they are, without Unicode
///   normalisation.
/// * `name` - A label for the account. May be empty.
/// * `derivationPath` - The path the keys were derived at, `m/44'/595'/{account}'/0/0`. Give it
///   when the keys came from `MasterSeed.deriveAccountKeys(account)`; leave it out otherwise.
///
/// # Returns
/// The key file, as JSON text.
///
/// # Errors
/// * Throws an error if `password` is empty.
/// * Throws an error if `derivationPath` isn't `m/44'/595'/{account}'/0/0` with an account from 0
///   to 2147483647.
///
/// # Example
/// ```javascript
/// const keys = MasterSeed.fromMnemonic(mnemonic).deriveAccountKeys(0);
/// const json = encryptKeyFile(keys, password, "Treasury", "m/44'/595'/0'/0/0");
/// ```
#[wasm_bindgen(js_name = encryptKeyFile)]
pub fn encrypt_key_file(
    keys: &AccountKeys,
    password: String,
    name: String,
    derivation_path: Option<String>,
) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .and_then(|_| rand::rngs::OsRng.try_fill_bytes(&mut nonce))
        .map_err(|_| JsValue::from_str("The system random number generator is unavailable"))?;
    let created = js_sys::Date::now();
    let created = if created.is_finite() && created >= 0.0 {
        created as u64
    } else {
        0
    };
    Ok(encrypt_with(
        &keys.inner,
        password.as_bytes(),
        &name,
        derivation_path.as_deref(),
        created,
        &salt,
        &nonce,
    )?)
}

/// Opens a DART key file (`docs/KEY_FILE_FORMAT.md`) with its password.
///
/// Key files written by polkadot.js `jsonEncrypt` with the DART fields open as well.
///
/// # Arguments
/// * `json` - The key file's JSON text.
/// * `password` - The password it was written with.
///
/// # Returns
/// A `DecryptedKeyFile` holding the account keys, name and derivation path.
///
/// # Errors
/// * "Invalid password or corrupted key file" if the password is wrong or the encrypted data was
///   modified. The two can't be told apart.
/// * "Unsupported key file" if the file isn't a DART key file, or uses a version, encoding or
///   scrypt parameters this library doesn't support.
/// * "Invalid key file: ..." if the file is malformed.
/// * "Key file public keys don't match its encrypted keys" if the clear-text public keys were
///   changed.
/// * "Corrupted key file: ..." if the decrypted data isn't valid account keys, or its public keys
///   don't match its secret keys.
///
/// # Example
/// ```javascript
/// const file = decryptKeyFile(json, password);
/// const keys = file.accountKeys();
/// ```
#[wasm_bindgen(js_name = decryptKeyFile)]
pub fn decrypt_key_file(json: String, password: String) -> Result<DecryptedKeyFile, JsValue> {
    let password = Zeroizing::new(password);
    let (fields, inner) = decrypt(&json, password.as_bytes())?;
    Ok(DecryptedKeyFile {
        name: fields.name,
        derivation_path: fields.derivation_path,
        created: fields.created,
        keys: AccountKeys { inner },
    })
}

/// The contents of a key file opened by `decryptKeyFile`.
///
/// `name` and `derivationPath` aren't authenticated by the encryption; don't base security
/// decisions on them.
#[wasm_bindgen]
pub struct DecryptedKeyFile {
    name: String,
    derivation_path: Option<String>,
    created: u64,
    keys: AccountKeys,
}

#[wasm_bindgen]
impl DecryptedKeyFile {
    /// The account's label. May be empty.
    #[wasm_bindgen(js_name = name)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// The path the keys were derived at, if the file records it. Informational only.
    #[wasm_bindgen(js_name = derivationPath)]
    pub fn derivation_path(&self) -> Option<String> {
        self.derivation_path.clone()
    }

    /// When the file was written (`meta.created`), in Unix milliseconds. Informational only: a
    /// host that re-encrypts the keys, for example to change the password, can keep it.
    ///
    /// Always an integer from 0 to 2^53 - 1, so it is exact as a JavaScript number.
    #[wasm_bindgen(js_name = created)]
    pub fn created(&self) -> f64 {
        // At most 2^53 - 1 (section 5.3), so the conversion is exact.
        self.created as f64
    }

    /// The account keys.
    #[wasm_bindgen(js_name = accountKeys)]
    pub fn account_keys(&self) -> AccountKeys {
        self.keys.clone()
    }
}

#[cfg(test)]
mod tests {
    //! The reference vectors, `tests/vectors/key-file-v1.json` (specification section 11).

    use super::*;
    use crate::MasterSeed;
    use serde::Deserialize;
    use serde_json::json;
    use wasm_bindgen_test::*;

    const VECTORS: &str = include_str!("../tests/vectors/key-file-v1.json");

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vectors {
        description: String,
        valid: Vec<ValidVector>,
        invalid: Vec<InvalidVector>,
    }

    /// The derivation vector (`tests/vectors/derivation-v1.json`) the keys come from.
    #[derive(Serialize, Deserialize, Clone)]
    struct KeySource {
        mnemonic: String,
        passphrase: String,
        account: u32,
    }

    #[derive(Serialize, Deserialize, Clone, Copy)]
    struct Params {
        #[serde(rename = "N")]
        n: u32,
        p: u32,
        r: u32,
    }

    #[derive(Serialize, Deserialize, Clone)]
    #[serde(rename_all = "camelCase")]
    struct ValidVector {
        description: String,
        /// The password; `passwordHex` is its UTF-8 bytes.
        password: String,
        password_hex: String,
        keys: KeySource,
        /// The plaintext: `AccountKeys.toSecretKeyHex()`.
        secret_key_hex: String,
        salt: String,
        nonce: String,
        scrypt: Params,
        encoded: String,
        file: Value,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InvalidVector {
        description: String,
        /// The section 7 step that rejects the file.
        step: u32,
        password: String,
        /// The file's text (it isn't always JSON).
        file: String,
        /// `invalid`, `unsupported`, `password`, `corrupted` or `publicKeyMismatch`.
        error: String,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(VECTORS).expect("key-file-v1.json parses")
    }

    fn native_keys(source: &KeySource) -> NativeAccountKeys {
        MasterSeed::from_mnemonic(source.mnemonic.clone(), Some(source.passphrase.clone()))
            .expect("valid mnemonic")
            .derive_account_keys(source.account as f64)
            .expect("valid account")
            .inner
            .clone()
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        hex::decode_to_slice(s.strip_prefix("0x").expect("0x prefix"), &mut out).expect("hex");
        out
    }

    fn category(e: &KeyFileError) -> &'static str {
        match e {
            KeyFileError::Invalid(_) => "invalid",
            KeyFileError::Unsupported => "unsupported",
            KeyFileError::InvalidPasswordOrCorrupted => "password",
            KeyFileError::Corrupted => "corrupted",
            KeyFileError::PublicKeyMismatch => "publicKeyMismatch",
            KeyFileError::Write(_) => "write",
        }
    }

    fn has_only_writer_meta(file: &Value) -> bool {
        file["meta"].as_object().map_or(false, |m| {
            m.keys().all(|k| k == "created" || k == "derivationPath")
        })
    }

    #[wasm_bindgen_test]
    fn valid_vectors_decrypt_to_the_expected_keys() {
        let vectors = vectors();
        assert!(vectors.valid.len() >= 7);
        for v in &vectors.valid {
            assert_eq!(
                hex0x(v.password.as_bytes()),
                v.password_hex,
                "{}",
                v.description
            );
            let keys = native_keys(&v.keys);
            assert_eq!(hex0x(&keys.encode()), v.secret_key_hex, "{}", v.description);
            assert_eq!(v.file["encoded"], json!(v.encoded), "{}", v.description);

            let (fields, opened) = decrypt(&v.file.to_string(), v.password.as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}", v.description, e.message()));
            assert!(opened == keys, "{}", v.description);
            assert_eq!(json!(fields.name), v.file["name"]);
            assert_eq!(json!(fields.created), v.file["meta"]["created"]);
            assert_eq!(
                fields
                    .derivation_path
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                v.file["meta"]
                    .get("derivationPath")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
    }

    #[wasm_bindgen_test]
    fn valid_vectors_reencrypt_byte_for_byte() {
        for v in vectors().valid {
            let salt = unhex::<SALT_LEN>(&v.salt);
            let nonce = unhex::<NONCE_LEN>(&v.nonce);
            let params = ScryptParams {
                n: v.scrypt.n,
                p: v.scrypt.p,
                r: v.scrypt.r,
            };
            let plaintext = unhex::<PLAINTEXT_LEN>(&v.secret_key_hex);

            let payload = seal(v.password.as_bytes(), &salt, &nonce, params, &plaintext)
                .unwrap_or_else(|e| panic!("{}: {}", v.description, e.message()));
            assert_eq!(
                base64_engine().encode(payload),
                v.encoded,
                "{}",
                v.description
            );

            // Files the writer produced come out identical (member order aside).
            if params == WRITE_PARAMS && has_only_writer_meta(&v.file) {
                let written = encrypt_with(
                    &native_keys(&v.keys),
                    v.password.as_bytes(),
                    v.file["name"].as_str().expect("name"),
                    v.file["meta"]["derivationPath"].as_str(),
                    v.file["meta"]["created"].as_u64().expect("created"),
                    &salt,
                    &nonce,
                )
                .unwrap_or_else(|e| panic!("{}: {}", v.description, e.message()));
                let written: Value = serde_json::from_str(&written).expect("writer JSON");
                assert_eq!(written, v.file, "{}", v.description);
            }
        }
    }

    #[wasm_bindgen_test]
    fn invalid_vectors_rejected() {
        let vectors = vectors();
        let steps: std::collections::BTreeSet<u32> =
            vectors.invalid.iter().map(|v| v.step).collect();
        assert_eq!(
            steps,
            (1..=10).collect(),
            "a vector for every step of section 7"
        );
        for v in vectors.invalid {
            let err = decrypt(&v.file, v.password.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("accepted: {}", v.description));
            assert_eq!(
                category(&err),
                v.error,
                "{}: {}",
                v.description,
                err.message()
            );
        }
    }

    /// Section 5: a duplicate member name. This reader (serde_json) keeps the last occurrence.
    #[wasm_bindgen_test]
    fn duplicate_member_uses_the_last_occurrence() {
        let v = &vectors().valid[0];
        let text = v.file.to_string();
        // A leading `"name": "Decoy"` before the real one.
        let duplicated = text.replacen('{', "{\"name\":\"Decoy\",", 1);
        assert!(duplicated.matches("\"name\"").count() == 2);
        let fields = parse(&duplicated).unwrap_or_else(|e| panic!("{}", e.message()));
        assert_eq!(json!(fields.name), v.file["name"]);
        // And the other way round.
        let duplicated = text.replacen('{', "{\"version\":2,", 1);
        assert!(parse(&duplicated).is_ok(), "the last `version`, 1, is used");
        let last_bad = format!("{},\"version\":2}}", &text[..text.len() - 1]);
        assert_eq!(parse(&last_bad).err(), Some(KeyFileError::Unsupported));
    }

    /// Section 5: a string that isn't valid Unicode (a lone surrogate escape) is rejected.
    #[wasm_bindgen_test]
    fn lone_surrogate_escape_rejected() {
        let v = &vectors().valid[0];
        let mut file = v.file.clone();
        file["name"] = json!("PLACEHOLDER");
        let text = file.to_string().replace("PLACEHOLDER", "\\ud800");
        assert!(text.contains("\"\\ud800\""));
        assert!(matches!(parse(&text), Err(KeyFileError::Invalid(_))));
        // A valid surrogate pair is fine.
        let text = file.to_string().replace("PLACEHOLDER", "\\ud83d\\udd11");
        assert_eq!(parse(&text).unwrap().name, "\u{1f511}");
    }

    /// Prints `tests/vectors/key-file-v1.json`. Native only; run it, then save the output:
    /// `cargo test --release --lib generate_key_file_vectors -- --ignored --nocapture`
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore]
    fn generate_key_file_vectors() {
        generator::print_vectors();
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod generator {
        use super::*;

        const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        const MAX: u32 = MAX_ACCOUNT as u32;

        fn source(mnemonic: &str, passphrase: &str, account: u32) -> KeySource {
            KeySource {
                mnemonic: mnemonic.to_string(),
                passphrase: passphrase.to_string(),
                account,
            }
        }

        fn path(account: u32) -> Option<String> {
            Some(format!("m/44'/595'/{}'/0/0", account))
        }

        struct Spec {
            description: &'static str,
            password: &'static str,
            keys: KeySource,
            params: ScryptParams,
            name: &'static str,
            derivation_path: Option<String>,
            created: u64,
        }

        fn valid_vectors() -> Vec<ValidVector> {
            let specs = vec![
                Spec {
                    description: "Writer parameters, with a derivation path",
                    password: "correct horse battery staple",
                    keys: source(ABANDON, "", 0),
                    params: WRITE_PARAMS,
                    name: "Treasury",
                    derivation_path: path(0),
                    created: 1764201600000,
                },
                Spec {
                    description: "A hex-looking password is its UTF-8 bytes (30 78 31 32 33 34), not hex-decoded; empty name; no derivation path",
                    password: "0x1234",
                    keys: source(ABANDON, "TREZOR", 1),
                    params: WRITE_PARAMS,
                    name: "",
                    derivation_path: None,
                    created: 1764201600001,
                },
                Spec {
                    description: "A non-ASCII password is its UTF-8 bytes without normalisation (it holds a decomposed a + U+0301 and the ligature U+FB01); the largest account; created = 0",
                    password: "pa\u{301}sswörd \u{fb01} 🔑",
                    keys: source(LEGAL, "TREZOR", MAX),
                    params: WRITE_PARAMS,
                    name: "Größe ✓ \"quoted\"",
                    derivation_path: path(MAX),
                    created: 0,
                },
                Spec {
                    description: "Reader-accepted parameters N = 2^15, p = 3, r = 8; created = 2^53 - 1",
                    password: "correct horse battery staple",
                    keys: source(ABANDON, "", 1),
                    params: ScryptParams { n: 1 << 15, p: 3, r: 8 },
                    name: "N=2^15 p=3",
                    derivation_path: path(1),
                    created: MAX_CREATED,
                },
                Spec {
                    description: "Reader-accepted parameters N = 2^15, p = 1, r = 8",
                    password: "correct horse battery staple",
                    keys: source(ABANDON, "", MAX),
                    params: ScryptParams { n: 1 << 15, p: 1, r: 8 },
                    name: "N=2^15 p=1",
                    derivation_path: path(MAX),
                    created: 1764201600003,
                },
                Spec {
                    description: "Reader-accepted parameters N = 2^16, p = 2, r = 8",
                    password: "correct horse battery staple",
                    keys: source(ABANDON, "TREZOR", 0),
                    params: ScryptParams { n: 1 << 16, p: 2, r: 8 },
                    name: "N=2^16 p=2",
                    derivation_path: path(0),
                    created: 1764201600004,
                },
            ];

            let mut valid = Vec::new();
            for (i, spec) in specs.into_iter().enumerate() {
                let salt: [u8; SALT_LEN] = core::array::from_fn(|b| (b + 32 * i) as u8);
                let nonce: [u8; NONCE_LEN] = core::array::from_fn(|b| (0xa0 + b + 24 * i) as u8);
                let plaintext: [u8; PLAINTEXT_LEN] =
                    native_keys(&spec.keys).encode().try_into().unwrap();
                let payload = seal(
                    spec.password.as_bytes(),
                    &salt,
                    &nonce,
                    spec.params,
                    &plaintext,
                )
                .unwrap();
                let fields = KeyFileFields {
                    name: spec.name.to_string(),
                    public_account: plaintext[64..96].try_into().unwrap(),
                    public_encryption: plaintext[0..32].try_into().unwrap(),
                    payload,
                    created: spec.created,
                    derivation_path: spec.derivation_path,
                };
                let file: Value = serde_json::from_str(&to_json(&fields).unwrap()).unwrap();
                valid.push(ValidVector {
                    description: spec.description.to_string(),
                    password: spec.password.to_string(),
                    password_hex: hex0x(spec.password.as_bytes()),
                    keys: spec.keys,
                    secret_key_hex: hex0x(&plaintext),
                    salt: hex0x(&salt),
                    nonce: hex0x(&nonce),
                    scrypt: Params {
                        n: spec.params.n,
                        p: spec.params.p,
                        r: spec.params.r,
                    },
                    encoded: base64_engine().encode(payload),
                    file,
                });
            }
            // A reader ignores `meta` members it doesn't know (section 5.3).
            let mut extra = valid[0].clone();
            extra.description = "Unknown meta members are ignored".to_string();
            extra.file["meta"]["app"] = json!({ "colour": "red", "tags": [1, 2] });
            valid.push(extra);
            valid
        }

        struct Invalid {
            base_file: Value,
            base_payload: Vec<u8>,
            vectors: Vec<InvalidVector>,
        }

        impl Invalid {
            /// Records a vector, after checking it fails as described.
            fn add(
                &mut self,
                step: u32,
                error: &str,
                description: &str,
                file: String,
                password: &str,
            ) {
                let err = decrypt(&file, password.as_bytes())
                    .err()
                    .unwrap_or_else(|| panic!("accepted: {}", description));
                assert_eq!(category(&err), error, "{}: {}", description, err.message());
                self.vectors.push(InvalidVector {
                    description: description.to_string(),
                    step,
                    password: password.to_string(),
                    file,
                    error: error.to_string(),
                });
            }

            fn edit(&self, f: impl FnOnce(&mut Value)) -> String {
                let mut v = self.base_file.clone();
                f(&mut v);
                serde_json::to_string_pretty(&v).unwrap()
            }

            fn remove(&self, member: &str) -> String {
                self.edit(|v| {
                    v.as_object_mut().unwrap().remove(member);
                })
            }

            fn with_encoded(&self, encoded: String) -> String {
                self.edit(|v| v["encoded"] = json!(encoded))
            }

            fn with_payload(&self, f: impl FnOnce(&mut Vec<u8>)) -> String {
                let mut p = self.base_payload.clone();
                f(&mut p);
                self.with_encoded(base64_engine().encode(&p))
            }

            fn with_params(&self, n: u32, p: u32, r: u32) -> String {
                self.with_payload(|payload| {
                    payload[32..36].copy_from_slice(&n.to_le_bytes());
                    payload[36..40].copy_from_slice(&p.to_le_bytes());
                    payload[40..44].copy_from_slice(&r.to_le_bytes());
                })
            }
        }

        fn invalid_vectors(valid: &[ValidVector]) -> Vec<InvalidVector> {
            let base = &valid[0];
            let pw = base.password.as_str();
            let mut t = Invalid {
                base_file: base.file.clone(),
                base_payload: base64_engine().decode(&base.encoded).unwrap(),
                vectors: Vec::new(),
            };
            let base_text = t.base_file.to_string();

            // Step 1.
            t.add(1, "invalid", "Not JSON", "dart-key-file".to_string(), pw);
            t.add(
                1,
                "invalid",
                "The top-level value is an array",
                "[]".to_string(),
                pw,
            );
            t.add(
                1,
                "invalid",
                "The top-level value is a string",
                "\"dart-key-file\"".to_string(),
                pw,
            );
            t.add(
                1,
                "invalid",
                "Trailing characters after the object",
                format!("{} x", base_text),
                pw,
            );

            // Step 2.
            let f = t.remove("type");
            t.add(2, "unsupported", "`type` missing", f, pw);
            let f = t.edit(|v| v["type"] = json!("Dart-Key-File"));
            t.add(2, "unsupported", "`type` has another value", f, pw);
            let polkadot_account = serde_json::to_string_pretty(&json!({
                "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
                "encoded": base.encoded,
                "encoding": {
                    "content": ["pkcs8", "sr25519"],
                    "type": ["scrypt", "xsalsa20-poly1305"],
                    "version": "3"
                },
                "meta": { "name": "Alice" }
            }))
            .unwrap();
            t.add(
                2,
                "unsupported",
                "A polkadot.js account file",
                polkadot_account,
                pw,
            );

            // Step 3.
            let f = t.edit(|v| v["version"] = json!(2));
            t.add(3, "unsupported", "`version` is 2", f, pw);
            let f = t.edit(|v| v["version"] = json!("1"));
            t.add(3, "unsupported", "`version` is the string \"1\"", f, pw);
            let f = t.remove("version");
            t.add(3, "unsupported", "`version` missing", f, pw);
            let f = t.edit(|v| {
                v["version"] = json!(2);
                v["encoded"] = json!("not base64");
            });
            t.add(
                3,
                "unsupported",
                "`version` 2 is rejected before `encoded` is looked at",
                f,
                pw,
            );

            // Step 4.
            let f = t.edit(|v| v["encoding"]["content"] = json!(["dart-mnemonic", "bip39-v1"]));
            t.add(4, "unsupported", "Reserved `dart-mnemonic` content", f, pw);
            let f = t.edit(|v| v["encoding"]["content"] = json!(["scale-v1", "dart-account-keys"]));
            t.add(
                4,
                "unsupported",
                "`encoding.content` in the wrong order",
                f,
                pw,
            );
            let f = t.edit(|v| v["encoding"]["type"] = json!(["none"]));
            t.add(
                4,
                "unsupported",
                "An unencrypted polkadot.js payload: `encoding.type` is [\"none\"]",
                f,
                pw,
            );
            let f = t.edit(|v| v["encoding"]["version"] = json!("2"));
            t.add(4, "unsupported", "`encoding.version` is \"2\"", f, pw);
            let f = t.edit(|v| v["encoding"]["version"] = json!(3));
            t.add(
                4,
                "unsupported",
                "`encoding.version` is the number 3",
                f,
                pw,
            );
            let f = t.remove("encoding");
            t.add(4, "unsupported", "`encoding` missing", f, pw);

            // Step 5.
            let f = t.remove("name");
            t.add(5, "invalid", "`name` missing", f, pw);
            let f = t.edit(|v| v["name"] = json!(null));
            t.add(5, "invalid", "`name` is not a string", f, pw);
            let f = t.edit(|v| v["extra"] = json!(true));
            t.add(5, "invalid", "An unknown top-level member", f, pw);
            let f = t.remove("public");
            t.add(5, "invalid", "`public` missing", f, pw);
            let f = t.edit(|v| v["public"]["extra"] = v["public"]["account"].clone());
            t.add(5, "invalid", "An unknown `public` member", f, pw);
            let f = t.edit(|v| v["encoding"]["extra"] = json!("x"));
            t.add(5, "invalid", "An unknown `encoding` member", f, pw);
            let f = t.edit(|v| {
                let s = v["public"]["account"].as_str().unwrap();
                v["public"]["account"] = json!(format!("0x{}", s[2..].to_uppercase()));
            });
            t.add(5, "invalid", "`public.account` in upper-case hex", f, pw);
            let f = t.edit(|v| {
                let s = v["public"]["encryption"].as_str().unwrap();
                v["public"]["encryption"] = json!(s[2..].to_string());
            });
            t.add(
                5,
                "invalid",
                "`public.encryption` without the 0x prefix",
                f,
                pw,
            );
            let f = t.edit(|v| {
                let s = v["public"]["account"].as_str().unwrap();
                v["public"]["account"] = json!(s[..64].to_string());
            });
            t.add(5, "invalid", "`public.account` of 31 bytes", f, pw);
            let f = t.edit(|v| v["encoded"] = json!(null));
            t.add(5, "invalid", "`encoded` is not a string", f, pw);
            let f = t.remove("meta");
            t.add(5, "invalid", "`meta` missing", f, pw);
            let f = t.edit(|v| {
                v["meta"].as_object_mut().unwrap().remove("created");
            });
            t.add(5, "invalid", "`meta.created` missing", f, pw);
            let f = t.edit(|v| v["meta"]["created"] = json!(-1));
            t.add(5, "invalid", "`meta.created` negative", f, pw);
            let f = t.edit(|v| v["meta"]["created"] = json!(1.5));
            t.add(5, "invalid", "`meta.created` fractional", f, pw);
            let f = t.edit(|v| v["meta"]["created"] = json!(MAX_CREATED + 1));
            t.add(5, "invalid", "`meta.created` above 2^53 - 1", f, pw);
            let f = t.edit(|v| v["meta"]["created"] = json!("1764201600000"));
            t.add(5, "invalid", "`meta.created` is a string", f, pw);
            let f = t.edit(|v| v["meta"]["derivationPath"] = json!("m/44'/595'/2147483648'/0/0"));
            t.add(
                5,
                "invalid",
                "`meta.derivationPath` account 2147483648 is out of range",
                f,
                pw,
            );
            let f = t.edit(|v| v["meta"]["derivationPath"] = json!("m/44'/595'/00'/0/0"));
            t.add(
                5,
                "invalid",
                "`meta.derivationPath` account with a leading zero",
                f,
                pw,
            );
            let f = t.edit(|v| v["meta"]["derivationPath"] = json!("m/44'/60'/0'/0/0"));
            t.add(
                5,
                "invalid",
                "`meta.derivationPath` with another coin type",
                f,
                pw,
            );
            let f = t.edit(|v| v["meta"]["derivationPath"] = json!(0));
            t.add(5, "invalid", "`meta.derivationPath` is not a string", f, pw);

            // Step 6.
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut bits = base.encoded.clone().into_bytes();
            let at = alphabet.iter().position(|c| *c == bits[282]).unwrap();
            bits[282] = alphabet[at ^ 1];
            let f = t.with_encoded(String::from_utf8(bits).unwrap());
            t.add(6, "invalid", "`encoded` with non-zero padding bits", f, pw);
            let f = t.with_encoded(base.encoded.trim_end_matches('=').to_string());
            t.add(6, "invalid", "`encoded` without its `=` padding", f, pw);
            let f = t.with_encoded(format!("{}\n{}", &base.encoded[..76], &base.encoded[76..]));
            t.add(6, "invalid", "`encoded` with a line break", f, pw);
            let f = t.with_encoded(format!("{} ", base.encoded));
            t.add(6, "invalid", "`encoded` with a trailing space", f, pw);
            let f = t.with_encoded(format!("-_{}", &base.encoded[2..]));
            t.add(6, "invalid", "`encoded` in the URL-safe alphabet", f, pw);
            let f = t.with_encoded(hex0x(&t.base_payload));
            t.add(6, "invalid", "`encoded` as hex", f, pw);
            let f = t.with_payload(|p| p.truncate(211));
            t.add(6, "invalid", "A 211-byte payload", f, pw);
            let f = t.with_payload(|p| p.push(0));
            t.add(6, "invalid", "A 213-byte payload", f, pw);

            // Step 7.
            let f = t.with_params(1 << 20, 1, 8);
            t.add(
                7,
                "unsupported",
                "N = 2^20, p = 1, r = 8, refused before running scrypt",
                f,
                pw,
            );
            let f = t.with_params(1 << 14, 5, 8);
            t.add(7, "unsupported", "N = 2^14, p = 5, r = 8 (a polkadot.js ALLOWED_PARAMS preset that fails its safe-limit check)", f, pw);
            let f = t.with_params(1 << 13, 10, 8);
            t.add(
                7,
                "unsupported",
                "N = 2^13, p = 10, r = 8 (likewise)",
                f,
                pw,
            );
            let f = t.with_params(1 << 17, 1, 16);
            t.add(7, "unsupported", "N = 2^17, p = 1, r = 16", f, pw);
            let f = t.with_params(1 << 17, 0, 8);
            t.add(7, "unsupported", "N = 2^17, p = 0, r = 8", f, pw);
            let f = t.with_params(1 << 18, 1, 8);
            t.add(
                7,
                "unsupported",
                "Unsupported parameters are reported before a wrong password",
                f,
                "wrong password",
            );

            // Step 8.
            t.add(
                8,
                "password",
                "A wrong password",
                base_text.clone(),
                "correct horse battery staple ",
            );
            let f = serde_json::to_string_pretty(&valid[1].file).unwrap();
            t.add(8, "password", "The bytes 12 34, which polkadot.js would hex-decode the string password \"0x1234\" to", f, "\u{12}\u{34}");
            let f = serde_json::to_string_pretty(&valid[2].file).unwrap();
            t.add(
                8,
                "password",
                "The NFC form of a decomposed password",
                f,
                "p\u{e1}sswörd \u{fb01} 🔑",
            );
            let f = t.with_payload(|p| p[0] ^= 1);
            t.add(8, "password", "A modified salt", f, pw);
            let f = t.with_payload(|p| p[50] ^= 1);
            t.add(8, "password", "A modified nonce", f, pw);
            let f = t.with_payload(|p| p[70] ^= 1);
            t.add(8, "password", "A modified tag", f, pw);
            let f = t.with_payload(|p| p[211] ^= 0x80);
            t.add(8, "password", "A modified ciphertext", f, pw);
            let f = t.edit(|v| v["public"]["account"] = v["public"]["encryption"].clone());
            t.add(
                8,
                "password",
                "A wrong password is reported before mismatched public keys",
                f,
                "wrong password",
            );

            // Step 9: correctly encrypted plaintexts that aren't valid `AccountKeys`.
            let plaintext: [u8; PLAINTEXT_LEN] = unhex(&base.secret_key_hex);
            let salt: [u8; SALT_LEN] = unhex(&base.salt);
            let nonce: [u8; NONCE_LEN] = unhex(&base.nonce);
            let sealed = |bad: [u8; PLAINTEXT_LEN]| {
                let payload = seal(pw.as_bytes(), &salt, &nonce, WRITE_PARAMS, &bad).unwrap();
                to_json(&KeyFileFields {
                    name: "Treasury".to_string(),
                    public_account: bad[64..96].try_into().unwrap(),
                    public_encryption: bad[0..32].try_into().unwrap(),
                    payload,
                    created: 1764201600000,
                    derivation_path: None,
                })
                .unwrap()
            };
            let mut bad_scalar = plaintext;
            bad_scalar[96..128].fill(0xff);
            t.add(
                9,
                "corrupted",
                "`acct.secret` is not below the Pallas group order",
                sealed(bad_scalar),
                pw,
            );
            let mut bad_scalar = plaintext;
            bad_scalar[32..64].fill(0xff);
            t.add(
                9,
                "corrupted",
                "`enc.secret` is not below the Pallas group order",
                sealed(bad_scalar),
                pw,
            );
            // Decodable, but inconsistent (section 3.2); `public` matches the plaintext.
            let mut flipped = plaintext;
            flipped[96] ^= 0x01;
            t.add(
                9,
                "corrupted",
                "`acct.secret` has a flipped bit: a valid scalar that doesn't match `acct.public`",
                sealed(flipped),
                pw,
            );
            let mut flipped = plaintext;
            flipped[32] ^= 0x01;
            t.add(
                9,
                "corrupted",
                "`enc.secret` has a flipped bit: a valid scalar that doesn't match `enc.public`",
                sealed(flipped),
                pw,
            );
            let mut not_a_point = plaintext;
            not_a_point[0..32].fill(0xff);
            t.add(
                9,
                "corrupted",
                "`enc.public` (and `public.encryption`) is 32 0xff bytes, not a Pallas point",
                sealed(not_a_point),
                pw,
            );

            // Step 10.
            let other = valid[3].file["public"].clone();
            let f = t.edit(|v| v["public"]["account"] = other["account"].clone());
            t.add(
                10,
                "publicKeyMismatch",
                "`public.account` is another account's",
                f,
                pw,
            );
            let f = t.edit(|v| v["public"]["encryption"] = other["encryption"].clone());
            t.add(
                10,
                "publicKeyMismatch",
                "`public.encryption` is another account's",
                f,
                pw,
            );
            let f = t.edit(|v| {
                let account = v["public"]["account"].clone();
                v["public"]["account"] = v["public"]["encryption"].clone();
                v["public"]["encryption"] = account;
            });
            t.add(
                10,
                "publicKeyMismatch",
                "`public.account` and `public.encryption` swapped",
                f,
                pw,
            );

            t.vectors
        }

        pub(super) fn print_vectors() {
            let valid = valid_vectors();
            let invalid = invalid_vectors(&valid);
            let vectors = Vectors {
                description: "DART key file version 1 reference vectors (docs/KEY_FILE_FORMAT.md, section 11). Each `valid` file MUST open with `password` (whose UTF-8 bytes are `passwordHex`) to the 128-byte plaintext `secretKeyHex`, the keys of the `keys` entry of tests/vectors/derivation-v1.json; encrypting `secretKeyHex` with `salt`, `nonce` and the `scrypt` parameters MUST reproduce `encoded` byte for byte. Each `invalid` file (JSON text) MUST be rejected, at step `step` of the reader procedure (section 7); `error` is the class of error: invalid, unsupported, password, corrupted or publicKeyMismatch.".to_string(),
                valid,
                invalid,
            };
            println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
        }
    }
}
