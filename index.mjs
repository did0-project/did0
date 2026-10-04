// did0 - Enterprise W3C DID & DePIN Cryptographic Engine (ESM)
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const did0 = require('./index.js');

export const {
  parseDID,
  verifySignature,
  encodeDidAttribute,
  encodeAddAttributeCall,
  encodeUpdateAttributeCall,
  encodeRemoveAttributeCall,
  canonicalize,
  issueCredential,
  generateMnemonic,
  validateMnemonic,
  createWallet,
} = did0;

export default did0;
