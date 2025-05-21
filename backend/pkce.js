// pkce.js
const crypto = require('crypto');

function base64URLEncode(str) {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeVerifier() {
  return base64URLEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(codeVerifier) {
  return base64URLEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );
}

// Exportamos las funciones
module.exports = {
  generateCodeVerifier,
  generateCodeChallenge
};
