// import libSodiumWrapper from "libsodium-wrappers";
// import ASN1 from "@lapo/asn1js";
// import Hex from "@lapo/asn1js/hex.js";
// import Base64 from "@lapo/asn1js/base64.js";
// const Defs = require("./defs.js")
const reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/

const gopalPrivateKey = "MC4CAQAwBQYDK2VwBCIEIC6rlrU/pOutsRE0xfXRWbDKhupiJrUzVDUUMPy5K4Rf"
const gopalPublicKey = "MCowBQYDK2VwAyEAVeiq3+fN3jjs3ud62BV0ABg1jtkBZp1tSgL3+WZU6A4="

const pavanPrivateKey = "MC4CAQAwBQYDK2VwBCIEIDGHMPTANF0o77IOt5gxiSYpb39HRSCkA2QxQYMq+FCR"
const pavanPublicKey = "MCowBQYDK2VwAyEAzvHggbwxzwT1KsniqoERCUX+dlUKrorfrejdHfKINBo="

function keyToUint8Arrray(key, type = "hex") {
    return Uint8Array.from(Buffer.from(key, type));
}


const ASN1 = require("@lapo/asn1js");
const Hex = require("@lapo/asn1js/hex.js");
const Base64 = require("@lapo/asn1js/base64.js");

function decodeTextASN_1(val, privateKey = false) {
    try {
        let der = reHex.test(val) ? Hex.decode(val) : Base64.unarmor(val);
        let ans1 = ASN1.decode(der)

        if (ans1.sub) {
            let t = ans1.sub[ans1.sub.length - 1]
            if (privateKey) {
                return t.stream.hexDump(t.posStart() + 4, t.posEnd(), true)
            }
            return t.stream.hexDump(t.posStart() + 3, t.posEnd(), true)
        }

        // let t = ans1.sub[2]
        // console.log(t.toHexString())
        // return t.stream.hexDump(t.posStart()+4, t.posEnd(),true)
    } catch (e) {
        console.error(e);
        throw new Error("Invalid key");
    }
}


// let gopaldecodedPrivateKey = keyToUint8Arrray(decodeTextASN_1(gopalPrivateKey,true))
// let gopaldecodedPublicKey = keyToUint8Arrray(decodeTextASN_1(gopalPublicKey))

// let pavandecodedPrivateKey = keyToUint8Arrray(decodeTextASN_1(pavanPrivateKey,true))
// let pavandecodedPublicKey = keyToUint8Arrray(decodeTextASN_1(pavanPublicKey))

// libSodiumWrapper.crypto_kx_client_session_keys(pavandecodedPublicKey,pavandecodedPrivateKey,gopaldecodedPublicKey)
// libSodiumWrapper.crypto_kx_server_session_keys(gopaldecodedPublicKey,gopaldecodedPrivateKey,pavandecodedPublicKey)


// // Import the necessary modules

// const nacl = require('tweetnacl');
// const util = require('tweetnacl-util');

// // Load the existing keys

// let clientKeyPair = exractKeysFromOpensslPem(gopalPrivateKey,gopalPublicKey)

// // Generate a key pair for the ephemeral (temporary) key
// // const ephemeralKeyPair = nacl.box.keyPair();
// let ephemeralKeyPair = exractKeysFromOpensslPem(pavanPrivateKey,pavanPublicKey)
// // Perform the key exchange
// const sharedSecretServer = nacl.box.before(clientKeyPair.publicKey, ephemeralKeyPair.privateKey);

// const sharedSecretClient = nacl.box.before(ephemeralKeyPair.publicKey, clientKeyPair.privateKey);


// // // Perform the key exchange
// // const sharedSecretServer = nacl.box.before(ephemeralKeyPair1.publicKey, ephemeralKeyPair2.secretKey);

// // const sharedSecretClient = nacl.box.before(ephemeralKeyPair2.publicKey, ephemeralKeyPair1.secretKey);

// // Print the shared secret
// const sharedSecretHexServer = util.encodeBase64(sharedSecretServer);

// const sharedSecretHexClient = util.encodeBase64(sharedSecretClient);

// console.log('Shared secret server:', sharedSecretHexServer);

// console.log('Shared secret client:', sharedSecretHexClient);

// function exractKeysFromOpensslPem(privateKeyRaw, publicKeyRaw) {
//     // Convert base64-encoded keys to Uint8Arrays
//     const privateKeyBytes = Uint8Array.from(atob(privateKeyRaw), c => c.charCodeAt(0));
//     const publicKeyBytes = Uint8Array.from(atob(publicKeyRaw), c => c.charCodeAt(0));

//     // Extract key components
//     const privateKey = privateKeyBytes.slice(0, 32); // First 32 bytes is the private key
//     const publicKey = publicKeyBytes.slice(0, 32);   // First 32 bytes is the public key

//     // Print the key components as hex strings
//     console.log('Private key:', Buffer.from(privateKey).toString('hex'));
//     console.log('Public key:', Buffer.from(publicKey).toString('hex'));
//     return { privateKey: privateKey, publicKey: publicKey}
// } 

const nacl = require('tweetnacl');
const fs = require('fs');

// Load server's private key
const serverPrivateKey = fs.readFileSync('openssl-keys/ed25519_openssl_1');
const serverKeyPair = nacl.sign.keyPair.fromSeed(gopalPrivateKey);

// Load client's private key
const clientPrivateKey = fs.readFileSync('openssl-keys/private.pem');
const clientKeyPair = nacl.sign.keyPair.fromSeed(pavanPrivateKey);

// Load server's public key
const serverPublicKey = gopalPublicKey;

// Load client's public key
const clientPublicKey = pavanPublicKey;

// Generate shared key on the client-side
const clientSharedKey = nacl.box.before(serverPublicKey, clientKeyPair.secretKey);

// Generate shared key on the server-side
const serverSharedKey = nacl.box.before(clientPublicKey, serverKeyPair.secretKey);

// Encode shared keys as Base64
const clientSharedKeyBase64 = Buffer.from(clientSharedKey).toString('base64');
const serverSharedKeyBase64 = Buffer.from(serverSharedKey).toString('base64');

console.log('Client shared key (Base64):', clientSharedKeyBase64);
console.log('Server shared key (Base64):', serverSharedKeyBase64);
