import figlet from "figlet";
import inquirer from 'inquirer';
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import os from "os";
import libSodiumWrapper from "libsodium-wrappers";
import {chalk, Chalk} from 'chalk-pipe';
import dotenv from 'dotenv'
dotenv.config()

const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);

if(!process.env.zKID_KEY_PATH) {
    process.env.zKID_KEY_PATH =  path.join(os.homedir(), "/.zKID");
}
const KeyPathFromEnv = process.env.zKID_KEY_PATH
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
                    (fs.existsSync(KeyPathFromEnv + '/privateKey') || fs.existsSync(KeyPathFromEnv + '/publicKey')) ?
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
                    message: "Location to store keys ? (If key is alrerady present in the directory, it will be replaced with new keys)",
                    default() {
                        return KeyPathFromEnv
                    },
                },).then((userInput) => {
                    
                    // console.log('keyPath', userInput)
                    keyStore(userInput.keyPath);
                }
                )
            } else if (answers.action === 'keyLocation') {
                console.log('Location:',chalk.blueBright(KeyPathFromEnv))
            } else {
                console.log("Unknown option")
            }
        });

}

function keyStore(destinationPath) {
    try {
        mkDirByPathSync(destinationPath);
        checkIfKeyExists(destinationPath)
        const generatedKey = libSodiumWrapper.crypto_sign_keypair("hex")
        storeKey(destinationPath, generatedKey);
        console.log(chalk.greenBright("Key Generated and stored successfully in:"),chalk.blueBright(destinationPath));
    } catch (error) {
        console.log("Error....")
        console.error(error);
    }
}

function storeKey(destinationPath, generatedKey) {
    process.env.zKID_PRIVATE_KEY = destinationPath;
    fs.writeFileSync(path.join(destinationPath, "privateKey"), generatedKey.privateKey, { mode: '400' });
    fs.writeFileSync(path.join(destinationPath, "publicKey"), generatedKey.publicKey);
}

function checkIfKeyExists(keyDir) {

    try {
        if (fs.existsSync(keyDir + '/privateKey') || fs.existsSync(keyDir + '/publicKey')) {
            fs.rmSync(keyDir + '/privateKey')
            fs.rmSync(keyDir + '/publicKey')
        }
    } catch (err) {
        console.log(`Key does no exist in ${filePath}`);

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
