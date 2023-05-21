const asn1 = require('asn1.js');
const elliptic = require('elliptic');
const forge = require('node-forge');
const fs = require('fs');
const { KeyPair } = require('elliptic').eddsa;
const nacl = require('tweetnacl');
const crypto = require('crypto');
const { decodeBase64, encodeBase64 } = require('tweetnacl-util');

const locationOfServerPrivateKey = 'openssl-keys/private_key_x25519.pem';
const locationOfServerPublicKey = 'openssl-keys/public_key_x25519.pem';
const locationClientPrivateKey = 'openssl-keys/private_key_x25519_2.pem';
const locationClientPublicKey = 'openssl-keys/public_key_x25519_2.pem';

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
console.log("serverPrivateKey",serverPrivateKey.toString('hex'));
console.log("serverPublicKey",serverPublicKey.toString('hex'));



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
console.log("clientPrivateKey",clientPrivateKey.toString('hex'));
console.log("clientPublicKey",clientPublicKey.toString('hex'));

// GENERATE SHARED KEY
// Generate shared key on the client-side
const clientSharedKey = nacl.box.before(serverPublicKey, clientPrivateKey);

// Generate shared key on the server-side
const serverSharedKey = nacl.box.before(clientPublicKey, serverPrivateKey);

// Encode shared keys as Base64
const clientSharedKeyBase64 = Buffer.from(clientSharedKey).toString('base64');
const serverSharedKeyBase64 = Buffer.from(serverSharedKey).toString('base64');

console.log('Client shared key (Base64):', clientSharedKeyBase64);
console.log('Server shared key (Base64):', serverSharedKeyBase64);
