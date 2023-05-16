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
                inquirer.prompt([{
                    type: 'input',
                    name: 'keyPath',
                    message: "Location to store keys ? (If key is alrerady present in the directory, it will be replaced with new keys)",
                    default() {
                        return KeyPathFromEnv
                    },
                },{
                    type: 'input',
                    name: 'keyName',
                    message: "Enter filename",
                    default() {
                        return 'id_ed25519'
                    },
                }]).then((userInput) => {
                    
                    // console.log('keyPath', userInput)
                    genKey(userInput);
                }
                )
            } else if (answers.action === 'keyLocation') {
                console.log('Location:',chalk.blueBright(KeyPathFromEnv))
            } else {
                console.log("Unknown option")
            }
        });

}

function genKey(destinationPathandName) {
    try {
        mkDirByPathSync(destinationPathandName.keyPath);
        // checkIfKeyExists(destinationPath)
        const generatedKey = libSodiumWrapper.crypto_sign_keypair("hex")
        saveKey(destinationPathandName, generatedKey);
        console.log(chalk.greenBright("Key Generated and saved successfully"));
        console.log(chalk.blueBright("Your private key has been saved in",`${destinationPathandName.keyPath}/${destinationPathandName.keyName}`));
        console.log(chalk.blueBright("Your public key has been saved in",`${destinationPathandName.keyPath}/${destinationPathandName.keyName}.pub`));
    } catch (error) {
        console.log("Error....")
        console.error(error);
    }
}

function saveKey(destinationPathandName, generatedKey) {
    process.env.zKID_KEY_PATH = destinationPathandName.keyPath;
    fs.writeFileSync(path.join(destinationPathandName.keyPath, `/${destinationPathandName.keyName}`), generatedKey.privateKey, { mode: '600' });
    fs.writeFileSync(path.join(destinationPathandName.keyPath, `/${destinationPathandName.keyName}.pub`), generatedKey.publicKey);
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
