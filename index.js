// index.js
const did0 = require('./did0.node');

function canonicalize(payload) {
  const jsonStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return did0.canonicalize(jsonStr);
}

function issueCredential(payload, privateKeyHex) {
  const jsonStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return did0.issueCredential(jsonStr, privateKeyHex);
}

function createWallet(options = {}) {
  const passphrase = options.passphrase || '';
  const mnemonic = options.mnemonic || '';
  return did0.createWallet(passphrase, mnemonic);
}

module.exports = {
  ...did0,
  canonicalize,
  issueCredential,
  createWallet,
};
