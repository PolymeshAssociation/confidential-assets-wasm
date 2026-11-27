// DART key file interop check: polkadot.js 13.5.9 <-> polymesh-dart-wasm, and the JSON Schema.
//
// Proves that the DART key file (docs/KEY_FILE_FORMAT.md) is byte-compatible with the polkadot.js
// keyring JSON encryption (`jsonEncrypt`/`jsonDecrypt` in @polkadot/util-crypto 13.5.9):
//
//   (a) a key file built with polkadot.js `jsonEncrypt` opens with `decryptKeyFile`;
//   (b) a key file written by `encryptKeyFile` opens with polkadot.js `jsonDecrypt`, to exactly
//       the `toSecretKeyHex()` bytes;
//   (c) both files, and every valid file in tests/vectors/key-file-v1.json, pass
//       schemas/dart-key-file-v1.schema.json (ajv, draft 2020-12);
//   (d) every valid vector opens with polkadot.js, and polkadot.js's own primitives reproduce its
//       `encoded` byte for byte from its salt, nonce and scrypt parameters.
//
// It exits non-zero on any failure.
//
// Run from the repository root:
//
//   wasm-pack build --release --target nodejs --out-dir pkg-node
//   npm ci --prefix scripts/key-file-interop
//   node scripts/key-file-interop/interop.mjs
//
// Set DART_WASM_PKG to load the wasm-pack output from another directory.
//
// `node scripts/key-file-interop/interop.mjs --emit-fixture` instead prints a new polkadot.js-made
// fixture, the content of tests/vectors/key-file-v1-polkadot-js.json.
//
// Passwords are always given to polkadot.js as Uint8Array (`stringToU8a`): polkadot.js
// hex-decodes a string password that looks like hex, such as "0x1234" (spec section 6.1).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { hexToU8a, stringToU8a, u8aConcat, u8aToHex } from '@polkadot/util';
import {
  base64Encode,
  cryptoWaitReady,
  jsonDecrypt,
  jsonEncrypt,
  jsonEncryptFormat,
  naclEncrypt,
  scryptEncode,
  scryptToU8a
} from '@polkadot/util-crypto';
import Ajv2020Module from 'ajv/dist/2020.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const pkgDir = path.resolve(process.env.DART_WASM_PKG ?? path.join(root, 'pkg-node'));

const require = createRequire(import.meta.url);
const dart = require(path.join(pkgDir, 'polymesh_dart_wasm.js'));

const CONTENT = ['dart-account-keys', 'scale-v1'];
const ABANDON_ABOUT =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORDS = ['correct horse battery staple', '0x1234', 'pásswörd ﬁ 🔑'];

const readJson = (relative) => JSON.parse(readFileSync(path.join(root, relative), 'utf8'));

/** A key file built by polkadot.js `jsonEncrypt` over the `toSecretKeyHex` bytes. */
function polkadotKeyFile (keys, password, name, account) {
  const secret = hexToU8a(keys.toSecretKeyHex());
  const { encoded, encoding } = jsonEncrypt(secret, CONTENT, stringToU8a(password));
  const meta = { created: Date.now() };
  if (account !== undefined) {
    meta.derivationPath = `m/44'/595'/${account}'/0/0`;
  }
  return {
    type: 'dart-key-file',
    version: 1,
    name,
    public: {
      account: u8aToHex(secret.subarray(64, 96)),
      encryption: u8aToHex(secret.subarray(0, 32))
    },
    encoded,
    encoding,
    meta
  };
}

function deriveKeys (passphrase, account) {
  return dart.MasterSeed.fromMnemonic(ABANDON_ABOUT, passphrase).deriveAccountKeys(account);
}

function timed (fn) {
  const start = performance.now();
  const result = fn();
  return [result, performance.now() - start];
}

async function emitFixture () {
  await cryptoWaitReady();
  const password = 'polkadot.js fixture 🔐';
  const keys = deriveKeys('TREZOR', 0);
  const file = polkadotKeyFile(keys, password, 'polkadot.js jsonEncrypt', 0);
  const fixture = {
    description:
      'A DART key file whose `encoded`/`encoding` were made by @polkadot/util-crypto 13.5.9 ' +
      '`jsonEncrypt(secretKeyHex bytes, ["dart-account-keys", "scale-v1"], stringToU8a(password))` ' +
      '(scripts/key-file-interop/interop.mjs --emit-fixture). Keys: the abandon...about mnemonic, ' +
      'passphrase "TREZOR", account 0.',
    password,
    secretKeyHex: keys.toSecretKeyHex(),
    file
  };
  process.stdout.write(JSON.stringify(fixture, null, 2) + '\n');
}

async function main () {
  await cryptoWaitReady();

  const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(readJson('schemas/dart-key-file-v1.schema.json'));
  const assertSchemaValid = (file, what) => {
    assert.ok(validate(file), `${what} fails the schema: ${ajv.errorsText(validate.errors)}`);
  };

  let checks = 0;

  for (const [i, password] of PASSWORDS.entries()) {
    const keys = deriveKeys('', i);
    const secretHex = keys.toSecretKeyHex();

    // (a) polkadot.js jsonEncrypt -> decryptKeyFile.
    const pjsFile = polkadotKeyFile(keys, password, `polkadot.js ${i}`, i);
    const [opened, openMs] = timed(() => dart.decryptKeyFile(JSON.stringify(pjsFile), password));
    assert.equal(opened.accountKeys().toSecretKeyHex(), secretHex, `(a) keys, password ${i}`);
    assert.equal(opened.name(), `polkadot.js ${i}`);
    assert.equal(opened.derivationPath(), `m/44'/595'/${i}'/0/0`);
    assert.equal(opened.created(), pjsFile.meta.created);
    assert.throws(
      () => dart.decryptKeyFile(JSON.stringify(pjsFile), password + 'x'),
      (e) => e === 'Invalid password or corrupted key file'
    );
    console.log(`ok (a) polkadot.js jsonEncrypt -> decryptKeyFile, password ${JSON.stringify(password)} (decryptKeyFile ${openMs.toFixed(0)} ms)`);

    // (b) encryptKeyFile -> polkadot.js jsonDecrypt.
    const [json, encryptMs] = timed(() =>
      dart.encryptKeyFile(keys, password, `wasm ${i}`, `m/44'/595'/${i}'/0/0`)
    );
    const dartFile = JSON.parse(json);
    const plaintext = jsonDecrypt(dartFile, stringToU8a(password));
    assert.equal(u8aToHex(plaintext), secretHex, `(b) plaintext, password ${i}`);
    assert.equal(plaintext.length, 128);
    console.log(`ok (b) encryptKeyFile -> polkadot.js jsonDecrypt, password ${JSON.stringify(password)} (encryptKeyFile ${encryptMs.toFixed(0)} ms)`);

    // (c) Both files against the schema.
    assertSchemaValid(pjsFile, `(c) polkadot.js file ${i}`);
    assertSchemaValid(dartFile, `(c) encryptKeyFile file ${i}`);
    console.log(`ok (c) both files pass the JSON Schema, password ${JSON.stringify(password)}`);
    checks += 3;
  }

  // The committed polkadot.js fixture.
  const fixture = readJson('tests/vectors/key-file-v1-polkadot-js.json');
  assertSchemaValid(fixture.file, 'polkadot.js fixture');
  assert.equal(
    u8aToHex(jsonDecrypt(fixture.file, stringToU8a(fixture.password))),
    fixture.secretKeyHex
  );
  assert.equal(
    dart.decryptKeyFile(JSON.stringify(fixture.file), fixture.password).accountKeys().toSecretKeyHex(),
    fixture.secretKeyHex
  );
  console.log('ok tests/vectors/key-file-v1-polkadot-js.json opens with both and passes the schema');
  checks += 1;

  // (d) The reference vectors.
  const vectors = readJson('tests/vectors/key-file-v1.json');
  assert.ok(vectors.valid.length > 0);
  for (const v of vectors.valid) {
    const password = hexToU8a(v.passwordHex);
    assert.deepEqual(password, stringToU8a(v.password), `${v.description}: passwordHex`);
    assertSchemaValid(v.file, v.description);
    assert.equal(u8aToHex(jsonDecrypt(v.file, password)), v.secretKeyHex, v.description);

    const { N, p, r } = v.scrypt;
    const salt = hexToU8a(v.salt);
    const key = scryptEncode(password, salt, { N, p, r }).password.subarray(0, 32);
    const { encrypted } = naclEncrypt(hexToU8a(v.secretKeyHex), key, hexToU8a(v.nonce));
    const payload = u8aConcat(scryptToU8a(salt, { N, p, r }), hexToU8a(v.nonce), encrypted);
    assert.equal(base64Encode(payload), v.encoded, `${v.description}: encoded`);
    assert.equal(jsonEncryptFormat(payload, CONTENT, true).encoded, v.encoded);
    console.log(`ok (d) vector reproduced by polkadot.js: ${v.description}`);
    checks += 1;
  }

  // The invalid vectors that the schema alone can catch must fail it.
  let schemaRejected = 0;
  for (const v of vectors.invalid) {
    let file;
    try {
      file = JSON.parse(v.file);
    } catch {
      continue;
    }
    if (!validate(file)) {
      schemaRejected += 1;
    } else {
      // Only steps the schema can't see may pass it.
      assert.ok([7, 8, 9, 10].includes(v.step), `invalid vector passes the schema: ${v.description}`);
    }
  }
  console.log(`ok the schema rejects ${schemaRejected} of ${vectors.invalid.length} invalid vectors; the rest need the reader procedure (steps 7 to 10) or aren't JSON`);
  checks += 1;

  console.log(`\nall ${checks} interop checks passed`);
}

const run = process.argv.includes('--emit-fixture') ? emitFixture : main;
run().catch((e) => {
  console.error('FAILED:', e);
  process.exit(1);
});
