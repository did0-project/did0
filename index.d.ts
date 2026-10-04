// index.d.ts

export interface DidDocument {
  /** The core W3C DID subject identifier */
  id: string;
  /** The multibase encoded public key, if present in the verification method */
  publicKeyMultibase?: string;
}

export interface Wallet {
  /** The BIP-39 mnemonic phrase (12 words for new wallets) */
  mnemonic: string;
  /**
   * 32-byte Ed25519 secret seed in hex (the Substrate "mini-secret").
   * Returned to JavaScript as a string, so it lives on the V8 heap and cannot be wiped.
   */
  privateKeyHex: string;
  /** 32-byte Ed25519 public key in hex */
  publicKeyHex: string;
  /** W3C `Ed25519VerificationKey2020` multibase public key (`z6Mk...`, multicodec 0xed01 prefix) */
  publicKeyMultibase: string;
  /** Substrate SS58 address in the requested prefix (default 42, generic Substrate) */
  ss58Address: string;
  /** W3C Decentralized Identifier: did:peaq:<ss58Address> */
  did: string;
}

export interface CreateWalletOptions {
  /** Optional passphrase for PBKDF2 salt (defaults to empty string) */
  passphrase?: string;
  /** Existing mnemonic phrase to restore wallet from */
  mnemonic?: string;
  /**
   * SS58 network prefix used for `ss58Address` and the `did:peaq:` identifier (0-16383).
   * Defaults to 42 (generic Substrate). peaq's registered prefix is 1221.
   */
  ss58Prefix?: number;
}

/**
 * Parses a W3C DID Document payload (at most 4095 bytes) and returns its `id` and the
 * `publicKeyMultibase` of the first verification method, if any.
 * Parsing runs in native code using a fixed stack buffer instead of the heap.
 *
 * @param payload The raw JSON string of the DID Document.
 * @throws If the payload is not valid JSON, does not fit the buffer, or is missing `id`.
 */
export function parseDID(payload: string): DidDocument;

/**
 * Verifies an Ed25519 signature over the raw message bytes.
 *
 * Use {@link verifyCredential} for signatures produced by {@link issueCredential};
 * those sign a SHA-256 digest and will (correctly) fail here.
 *
 * @param publicKeyMultibase `z`-prefixed base58btc Ed25519 key: either the W3C form with
 *   the 0xed01 multicodec prefix (`z6Mk...`) or the bare 32-byte key.
 * @param message The signed message (string up to 64 KiB, or any Buffer).
 * @param signatureHex The 128-character (64-byte) hex signature.
 * @returns `false` for a well-formed but invalid signature.
 * @throws If the key or signature are malformed.
 */
export function verifySignature(publicKeyMultibase: string, message: string | Buffer, signatureHex: string): boolean;

/**
 * Verifies an Ed25519 signature over SHA-256(message).
 * Lower-level building block of {@link verifyCredential}.
 */
export function verifyDigestSignature(publicKeyMultibase: string, message: string | Buffer, signatureHex: string): boolean;

/**
 * Verifies a signature produced by {@link issueCredential}: canonicalizes `payload`
 * with RFC 8785 and checks the Ed25519 signature over its SHA-256 digest.
 *
 * @param payload The same credential object or JSON string that was signed.
 * @param signatureHex The signature returned by `issueCredential`.
 * @param publicKeyMultibase The issuer's multibase public key.
 */
export function verifyCredential(payload: object | string, signatureHex: string, publicKeyMultibase: string): boolean;

/**
 * Substrate SCALE encoding of a peaq DID attribute (fixed-buffer, no heap).
 * 
 * @param didAccountHex 64-character hex string representing the 32-byte AccountId
 * @param name Attribute name (max 255 bytes, e.g. "did/pubkey")
 * @param value Attribute payload value (max 8191 bytes)
 * @param validity Validity block count/number
 * @returns Buffer containing SCALE-encoded bytes
 */
export function encodeDidAttribute(
  didAccountHex: string,
  name: string,
  value: string,
  validity: number
): Buffer;

/**
 * Encodes a Substrate dispatchable call for peaq-did `add_attribute`.
 * 
 * @param palletIndex Pallet index (0-255). Chain-specific: take it from the target runtime's metadata.
 * @param callIndex Call index inside the pallet (0-255), also from runtime metadata
 * @param didAccountHex 64-character hex string representing the 32-byte AccountId
 * @param name Attribute name
 * @param value Attribute payload value
 * @param validity Validity block count/number
 * @returns Buffer containing SCALE-encoded call extrinsic bytes
 */
export function encodeAddAttributeCall(
  palletIndex: number,
  callIndex: number,
  didAccountHex: string,
  name: string,
  value: string,
  validity: number
): Buffer;

/**
 * Encodes a Substrate dispatchable call for peaq-did `update_attribute`.
 * 
 * @param palletIndex Pallet index (0-255). Chain-specific: take it from the target runtime's metadata.
 * @param callIndex Call index inside the pallet (0-255), also from runtime metadata
 * @param didAccountHex 64-character hex string representing the 32-byte AccountId
 * @param name Attribute name
 * @param value Updated attribute payload value
 * @param validity Validity block count/number
 * @returns Buffer containing SCALE-encoded call extrinsic bytes
 */
export function encodeUpdateAttributeCall(
  palletIndex: number,
  callIndex: number,
  didAccountHex: string,
  name: string,
  value: string,
  validity: number
): Buffer;

/**
 * Encodes a Substrate dispatchable call for peaq-did `remove_attribute`.
 * 
 * @param palletIndex Pallet index (0-255). Chain-specific: take it from the target runtime's metadata.
 * @param callIndex Call index inside the pallet (0-255), also from runtime metadata
 * @param didAccountHex 64-character hex string representing the 32-byte AccountId
 * @param name Attribute name to remove
 * @returns Buffer containing SCALE-encoded call extrinsic bytes
 */
export function encodeRemoveAttributeCall(
  palletIndex: number,
  callIndex: number,
  didAccountHex: string,
  name: string
): Buffer;

/**
 * Canonicalizes a JSON object or string according to the JSON Canonicalization Scheme (RFC 8785).
 *
 * @param payload The raw JSON string or JavaScript object (serialized size under 64 KiB).
 * @returns The RFC 8785 canonical JSON string.
 */
export function canonicalize(payload: object | string): string;

/**
 * Signs a credential: canonicalizes it (RFC 8785), hashes it with SHA-256 and signs the
 * digest with Ed25519. This is a did0-specific scheme, not a W3C Data Integrity cryptosuite,
 * and the returned value is a bare signature rather than a `proof` object.
 *
 * @param payload The Verifiable Credential payload (JS object or JSON string).
 * @param privateKeyHex 64-character hex seed, 128-character hex (seed + public key), or base58 of 32/64 bytes.
 * @returns 128-character hex Ed25519 signature.
 */
export function issueCredential(payload: object | string, privateKeyHex: string): string;

/**
 * Generates a cryptographically secure BIP-39 mnemonic phrase.
 * 
 * @param wordCount Number of words (12 or 24, defaults to 12).
 * @returns Space-separated mnemonic string.
 */
export function generateMnemonic(wordCount?: 12 | 24): string;

/**
 * Validates a BIP-39 mnemonic phrase (word validity and checksum).
 * 
 * @param mnemonic The space-separated mnemonic phrase.
 * @returns True if the mnemonic is valid.
 */
export function validateMnemonic(mnemonic: string): boolean;

/**
 * Creates or restores an identity wallet.
 *
 * Key derivation follows Substrate tooling (polkadot-js `mnemonicToMiniSecret`): the Ed25519
 * seed is PBKDF2-HMAC-SHA512 over the mnemonic's entropy, so the same phrase yields the same
 * Ed25519 account in Polkadot.js-compatible wallets. Derivation runs natively, but the
 * resulting mnemonic and `privateKeyHex` are returned to JavaScript as strings.
 * 
 * @param options Optional configuration including passphrase and existing mnemonic.
 * @returns Complete Wallet object.
 */
export function createWallet(options?: CreateWalletOptions): Wallet;
