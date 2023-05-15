import figlet from "figlet";
import inquirer from 'inquirer';
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import os from "os";
import libSodiumWrapper from "libsodium-wrappers";
import tweetnaclUtil from "tweetnacl-util";

const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);


const pivateKeyPathFromEnv = process.env.zKID_PRIVATE_KEY
const publicKeyPathFromEnv = process.env.zKID_PUBLIC_KEY
figlet("zKID Keystore", function (err, data) {
    if (err) {
        console.log("Something went wrong...");
        console.dir(err);
        return;
    }
    console.log(data);
    options();
});

function options() {
    inquirer
        .prompt([
            {
                type: 'list',
                name: 'action',
                message: 'What do you want to do?',
                choices: [
                    { name: 'Generate Keypair', value: 'genKeyPair' },
                    pivateKeyPathFromEnv ?
                        {
                            name: 'Location of key', value: 'keyLocation'
                        } : {
                            name: 'Location of key',
                            disabled: 'Keys not yet generated',
                        },
                ],
            },

        ])
        .then((answers) => {
            if (answers.action === 'genKeyPair') {
                inquirer.prompt({
                    type: 'input',
                    name: 'keyPath',
                    message: "Location to store keys ?",
                    default() {
                        return path.join(os.homedir(), "/.ssh/zKID");
                    },
                },).then((userInput) => {
                    // console.log('keyPath', userInput)
                    generateKeys(userInput);
                }
                )
            } else if (answers.action === 'keyLocation') {
                console.log('keyLocation');
            } else {
                console.log("Unknown option")
            }
        });

}

function generateKeys(userInput) {
    try {
        mkDirByPathSync(userInput.keyPath);
        const keys = libSodiumWrapper.crypto_sign_keypair()
        let keyObj = { publicKey: tweetnaclUtil.encodeBase64(keys.publicKey),privateKey: tweetnaclUtil.encodeBase64(keys.privateKey),keyType:keys.keyType }
        fs.writeFileSync(path.join(userInput.keyPath,"key.json"),JSON.stringify(keyObj))
        // fs.writeFileSync(path.join(userInput.keyPath,"private.pem"), Buffer.from(keyObj.privateKey,'base64'))

    } catch (error) {
        console.log("Error....")
        console.error(error);
    }
}

function mkDirByPathSync(targetDir, { isRelativeToScript = false } = {}) {
    const sep = path.sep;
    const initDir = path.isAbsolute(targetDir) ? sep : '';
    const baseDir = isRelativeToScript ? __dirname : '.';

    return targetDir.split(sep).reduce((parentDir, childDir) => {
        const curDir = path.resolve(baseDir, parentDir, childDir);
        try {
            fs.mkdirSync(curDir);
        } catch (err) {
            if (err.code === 'EEXIST') { // curDir already exists!
                return curDir;
            }

            // To avoid `EISDIR` error on Mac and `EACCES`-->`ENOENT` and `EPERM` on Windows.
            if (err.code === 'ENOENT') { // Throw the original parentDir error on curDir `ENOENT` failure.
                throw new Error(`EACCES: permission denied, mkdir '${parentDir}'`);
            }

            const caughtErr = ['EACCES', 'EPERM', 'EISDIR'].indexOf(err.code) > -1;
            if (!caughtErr || caughtErr && curDir === path.resolve(targetDir)) {
                throw err; // Throw if it's just the last created dir.
            }
        }

        return curDir;
    }, initDir);
}
