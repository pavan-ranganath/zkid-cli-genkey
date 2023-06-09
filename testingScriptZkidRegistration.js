const asn1 = require('asn1.js');

const fs = require('fs');
const eddsa = require('elliptic');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');

var ed2curve = require('ed2curve');
// const locationOfServerPrivateKey = 'openssl-keys/private_key_x25519.pem';
// const locationOfServerPublicKey = 'openssl-keys/public_key_x25519.pem';
// const locationClientPrivateKey = 'openssl-keys/private_key_x25519_2.pem';
// const locationClientPublicKey = 'openssl-keys/public_key_x25519_2.pem';

const locationOfServerPrivateKey = 'openssl-keys/ed25519_openssl_1';
const locationOfServerPublicKey = 'openssl-keys/ed25519_openssl_1.pub';
const locationClientPrivateKey = 'openssl-keys/private.pem';
const locationClientPublicKey = 'openssl-keys/public.pem';

// const nobleEd25519 = require('@noble/ed25519')
// const locationOfServerPrivateKey = 'openssl-keys/rsa_private.pem';
// const locationOfServerPublicKey = 'openssl-keys/rsa_public.pem';
// const locationClientPrivateKey = 'openssl-keys/rsa_private_1.pem';
// const locationClientPublicKey = 'openssl-keys/rsa_public_1.pem';


// Load the key pair from PEM files

const readKeysFromPem = (publicKey, privateKey) => {
    const pemToBuffer = (pem) => Buffer.from(pem
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\n/g, ''), 'base64');

    const publicKeyBuffer = pemToBuffer(publicKey);
    const privateKeyBuffer = pemToBuffer(privateKey);

    return {
        publicKey: publicKeyBuffer,
        privateKey: privateKeyBuffer,
    };
};

// Define the ASN.1 schema for Ed25519 private keys
const Ed25519PrivateKey = asn1.define('Ed25519PrivateKey', function () {
    return this.seq().obj(
        this.key('tbsCertificate').int(),
        this.key('signatureAlgorithm').seq().obj(
            this.key('algorithm').objid()
        ),
        this.key('key').octstr().obj(
            this.key('privateKey').octstr()
        ),
    );
});

// ASN.1 schema for Ed25519 public key
const Ed25519PublicKey = asn1.define('PublicKey', function () {
    this.seq().obj(
        this.key('tbsCertificate').seq().obj(
            this.key('signatureAlgorithm').objid(),
        ),
        this.key('signatureValue').bitstr()
    );
});


// SERVER SIDE
const serverPrivateKeyPem = fs.readFileSync(locationOfServerPrivateKey, 'utf8');

const serverPublicKeyPem = fs.readFileSync(locationOfServerPublicKey, 'utf8');

const { publicKey: extractedServerPublicKey, privateKey: extractedServerPrivateKey } = readKeysFromPem(serverPublicKeyPem, serverPrivateKeyPem);

// Parse the ASN.1 private key
const parsedServerPrivateKey = Ed25519PrivateKey.decode(Buffer.from(extractedServerPrivateKey, 'hex'), 'der');
const parsedServerPublicKey = Ed25519PublicKey.decode(Buffer.from(extractedServerPublicKey, 'hex'), 'der');

// Extract the private key value
const serverPrivateKey = parsedServerPrivateKey.key.privateKey;
const serverPublicKey = parsedServerPublicKey.signatureValue.data;

// Display the extracted key
console.log("serverPrivateKey", serverPrivateKey.toString('hex'));
console.log("serverPublicKey", serverPublicKey.toString('hex'));



// CLIENT SIDE
const clientPrivateKeyPem = fs.readFileSync(locationClientPrivateKey, 'utf8');
const clientPublicKeyPem = fs.readFileSync(locationClientPublicKey, 'utf8');

const { publicKey: extractedclientPublicKey, privateKey: extractedclientPrivateKey } = readKeysFromPem(clientPublicKeyPem, clientPrivateKeyPem);

// Parse the ASN.1 private key
const parsedclientPrivateKey = Ed25519PrivateKey.decode(Buffer.from(extractedclientPrivateKey, 'hex'), 'der');
const parsedclientPublicKey = Ed25519PublicKey.decode(Buffer.from(extractedclientPublicKey, 'hex'), 'der');

// Extract the private key value
const clientPrivateKey = parsedclientPrivateKey.key.privateKey;
const clientPublicKey = parsedclientPublicKey.signatureValue.data;


// Display the extracted key
console.log("clientPrivateKey", clientPrivateKey.toString('hex'));
console.log("clientPublicKey", clientPublicKey.toString('hex'));


let convertedServerPrivateKey = ed2curve.convertSecretKey(serverPrivateKey)
let convertedServerPublicKey = ed2curve.convertPublicKey(serverPublicKey)

const toHexString = (bytes) => {
    return Array.from(bytes, (byte) => {
      return ('0' + (byte & 0xff).toString(16)).slice(-2);
    }).join('');
  };

let convertedClientPrivateKey = ed2curve.convertSecretKey(clientPrivateKey)
let convertedClientPublicKey = ed2curve.convertPublicKey(clientPublicKey)


// GENERATE SHARED KEY
// Generate shared key on the client-side
const clientSharedKey = nacl.box.before(convertedServerPublicKey, convertedClientPrivateKey);

// Generate shared key on the server-side
const serverSharedKey = nacl.box.before(convertedClientPublicKey, convertedServerPrivateKey);

// Encode shared keys as Base64
const clientSharedKeyBase64 = Buffer.from(clientSharedKey).toString('base64');
const serverSharedKeyBase64 = Buffer.from(serverSharedKey).toString('base64');

console.log('Client shared key (Base64):', clientSharedKeyBase64);
console.log('Server shared key (Base64):', serverSharedKeyBase64);

// Encrypt the message using the shared key
function encryptString(message, sharedKey) {
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const messageUint8 = util.decodeUTF8(message);
    const encrypted = nacl.box.after(messageUint8, nonce, sharedKey);
    const encryptedMessage = new Uint8Array(nonce.length + encrypted.length);
    encryptedMessage.set(nonce);
    encryptedMessage.set(encrypted, nonce.length);
    return util.encodeBase64(encryptedMessage);
}

// Decrypt the encrypted message using the shared key
function decryptString(encryptedMessage, sharedKey) {
    const encryptedMessageUint8 = util.decodeBase64(encryptedMessage);
    const nonce = encryptedMessageUint8.slice(0, nacl.box.nonceLength);
    const message = encryptedMessageUint8.slice(nacl.box.nonceLength);
    const decrypted = nacl.box.open.after(message, nonce, sharedKey);
    if (!decrypted) {
        throw new Error('Failed to decrypt message.');
    }
    return util.encodeUTF8(decrypted);
}

// Example usage
const message = "cf98d980c7e479ebd9fad6c568d03ebc05b7497086376222f30403d9fa6ad601";
const encryptedMessage = encryptString(message, serverSharedKey);
const decryptedMessage = decryptString(encryptedMessage, clientSharedKey);


console.log('Original message:', message);
console.log(`Encrypted '${message}' using serverSharedKey:`, encryptedMessage);
console.log(`Decrypted '${encryptedMessage}' using clientSharedKey:`, decryptedMessage);