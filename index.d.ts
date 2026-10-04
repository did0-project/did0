// index.d.ts

export interface DidDocument {
  /** The core W3C DID subject identifier */
  id: string;
  /** The multibase encoded public key, if present in the verification method */
  publicKeyMultibase?: string;
}

export interface Wallet {
  /** The BIP-39 mnemonic phrase (12 words) */
  mnemonic: string;
  /** 512-bit (64-byte) master seed in hex */
  seedHex: string;
  /** 32-byte Ed25519 secret seed in hex */
  privateKeyHex: string;
  /** 32-byte Ed25519 public key in hex */
  publicKeyHex: string;
  /** 'z' prefixed multibase base58 encoded public key */
  publicKeyMultibase: string;
  /** Substrate SS58 address (Prefix 42 for peaq/Substrate) */
  ss58Address: string;
  /** W3C Decentralized Identifier: did:peaq:<ss58Address> */
  did: string;
}

export interface CreateWalletOptions {
  /** Optional passphrase for PBKDF2 salt (defaults to empty string) */
  passphrase?: string;
  /** Existing mnemonic phrase to restore wallet from */
  mnemonic?: string;
}

/**
 * Parses a peaq network W3C DID Document payload.
 * Executes natively in Zig with zero heap allocations.
 * 
 * @param payload The raw JSON string of the DID Document.
 * @returns The extracted Document fields.
 */
export function parseDID(payload: string): DidDocument;

/**
 * Verifies a message signature against a multibase public key.
 * Executes mathematically via Zig's native Ed25519 standard library.
 * Supports raw messages as well as SHA-256 digested VC payloads.
 * 
 * @param publicKeyMultibase The 'z' prefixed base58 encoded public key.
 * @param message The raw challenge message or canonical VC string that was signed.
 * @param signatureHex The 128-character (64-byte) hex string of the signature.
 * @returns True if the signature is cryptographically valid.
 */
export function verifySignature(publicKeyMultibase: string, message: string | Buffer, signatureHex: string): boolean;

/**
 * Zero-allocation Substrate SCALE encoding for peaq DID attributes.
 * Formats a DID document / attribute payload into Substrate-compatible bytecodes.
 * 
 * @param didAccountHex 64-character hex string representing the 32-byte AccountId
 * @param name Attribute name (e.g. "did/pubkey" or DID identifier)
 * @param value Attribute payload value (e.g. W3C DID document string or public key)
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
 * @param palletIndex Pallet index in the Substrate runtime
 * @param callIndex Call index inside the pallet
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
 * @param palletIndex Pallet index in the Substrate runtime
 * @param callIndex Call index inside the pallet
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
 * @param palletIndex Pallet index in the Substrate runtime
 * @param callIndex Call index inside the pallet
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
 * Performs zero-allocation AST parsing and recursive UTF-16 code unit key sorting in native Zig.
 * 
 * @param payload The raw JSON string or JavaScript object to canonicalize.
 * @returns The RFC 8785 canonical JSON string.
 */
export function canonicalize(payload: object | string): string;

/**
 * Issues and signs a W3C Verifiable Credential on the peaq network.
 * Canonicalizes the credential payload using RFC 8785 (JCS), hashes it using SHA-256,
 * and signs it with native Ed25519 completely off the V8 heap.
 * 
 * @param payload The Verifiable Credential payload (JS object or JSON string).
 * @param privateKeyHex A 64-character (32-byte seed) hex string, 128-character hex string, or Base58 string.
 * @returns 128-character hex string of the Ed25519 cryptographic signature.
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
 * Creates or restores a peaq DePIN identity wallet natively in Zig.
 * Generates/validates BIP-39 mnemonics, computes PBKDF2 seed, derives Ed25519 keypair,
 * SS58 address, and W3C DID entirely off the JavaScript heap.
 * 
 * @param options Optional configuration including passphrase and existing mnemonic.
 * @returns Complete Wallet object.
 */
export function createWallet(options?: CreateWalletOptions): Wallet;
