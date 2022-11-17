const { randomBytes } = require('crypto');
const { NFC } = require('nfc-pcsc');
const EC = require('elliptic').ec;
const ethers = require('ethers');
const sha256 = require('js-sha256').sha256;
const queryString = require('query-string');

const ec = new EC('secp256k1');

const ATTEST_KEYS = {
    0xA0: {
        name: "Airtime Network Inc. Attestation key #0",
        publicKey: "0436de4602f2d85d9cbd4deac220173b4e9f32aae7e808278aa34d6c6a88482b4353b22e017b02427a5f8b71d042c0a444886169ef09371652a33504c834f0aff9"
    }
};

const nfc = new NFC();
let cb = null;
let timeout = null;
let isClosing = false;
let args = process.argv.slice(2);

async function signChallenge(execCmd, keyNo, challengeHash) {
    let payload = Buffer.concat([
        Buffer.from([0x01, keyNo]),
        Buffer.from(challengeHash, "hex")
    ]);

    return await execCmd(payload);
}

async function readPublicKeys(execCmd) {
    let payload = Buffer.from("02", "hex");
    let res = await execCmd(payload);

    let pkey1;
    let pkey2;
    let pkey3 = null;

    pkey1 = res.slice(1, res[0] + 1).toString('hex');
    res = res.slice(1 + res[0]);

    pkey2 = res.slice(1, res[0] + 1).toString('hex');
    res = res.slice(1 + res[0]);

    if (res.length > 0) {
        pkey3 = res.slice(1, res[0] + 1).toString('hex');
    }

    return {pkey1, pkey2, pkey3};
}

async function getLatch(execCmd, slotNo) {
    let payload = Buffer.from([0xD1, slotNo]);
    let res = await execCmd(payload);

    if (res.length === 2 && res[0] === 0xe1) {
        if (res[1] === 0x09) {
            return null;
        } else {
            throw Error('getLatch failed with error code: ' + res.toString('hex'));
        }
    }

    return res.toString('hex');
}

async function storeLatchData(execCmd, slotNo, latchData) {
    let payload = Buffer.concat([
        Buffer.from([0xD3, slotNo]),
        Buffer.from(latchData)
    ]);
    return await execCmd(payload);
}

if (args[0] === "sign" || args[0] === "sign_raw") {
    let rawSigning = (args[0] === "sign_raw");

    cb = async (execCmd) => {
        let keyNo = parseInt(args[1]);
        let challengeHash = args[2];
        let inputDataObj = {};

        if (!rawSigning) {
            let dataBuf = Buffer.from(challengeHash, 'hex');
            challengeHash = ethers.utils.hashMessage(dataBuf).slice(2);
            inputDataObj = {"data": dataBuf.toString('hex')};
        }

        let pkeys = await readPublicKeys(execCmd);
        let res = await signChallenge(execCmd, keyNo, challengeHash);

        if (res[0] === 0xE1 && res.length === 2) {
            return {"error": "Tag returned error code: " + res.toString('hex')};
        }

        let key = ec.keyFromPublic(pkeys['pkey' + keyNo].toString('hex'), 'hex');
        if (!key.verify(challengeHash, res)) {
            return {"error": "Invalid signature returned by the tag (1)."};
        }

        if (res[0] !== 0x30 || res[2] !== 0x02) {
            return {"error": "Invalid signature returned by the tag (2)."};
        }

        let rLen = res[3];

        if (res[rLen+4] !== 0x02) {
            return {"error": "Invalid signature returned by the tag (3)."}
        }

        let sLen = res[rLen+5];

        if (res.length !== rLen+4+2+sLen) {
            return {"error": "Invalid signature returned by the tag (4)."};
        }

        let r = res.slice(4, rLen+4);
        let s = res.slice(rLen+4+2, rLen+4+2+sLen);
        let rn = BigInt('0x' + r.toString('hex'));
        let sn = BigInt('0x' + s.toString('hex'));

        // SECP256k1 order constant
        let curveOrder = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;

        if (sn > curveOrder / 2n) {
            // malleable signature, not compliant with Ethereum's EIP-2
            // we need to flip s value in the signature
            sn = -sn + curveOrder;
        }

        let fixedSig = {r: rn.toString(16), s: sn.toString(16)};
        let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
        let recoveryParam = null;

        for (let i = 0; i < 2; i++) {
            if (pkeys['pkey' + keyNo] === ec.recoverPubKey(hexToDecimal(challengeHash), fixedSig, i).encode('hex')) {
                recoveryParam = i;
                break;
            }
        }

        if (recoveryParam === null) {
            return {"error": "Failed to get recovery param."};
        }

        let finalSig = '0x' + rn.toString(16).padStart(64, '0')
            + sn.toString(16).padStart(64, '0')
            + Buffer.from([27 + recoveryParam]).toString('hex');

        let pkeyAddress = ethers.utils.computeAddress('0x' + pkeys['pkey' + keyNo]);
        let recoveredAddress = ethers.utils.recoverAddress('0x' + challengeHash, finalSig);

        if (pkeyAddress !== recoveredAddress) {
            return {"error": "Failed to correctly recover public key from the signature."};
        }

        return {
            "operation": {
                "keyNumber": keyNo,
                "publicKey": pkeys['pkey' + keyNo].toString('hex'),
                "digest": challengeHash,
                ...inputDataObj
            },
            "signature": {
                "raw": {
                    ...fixedSig,
                    recoveryParam
                },
                "der": res.toString('hex'),
                "ether": finalSig.toString('hex')
            }
        };
    };
} else if (args[0] === "store") {
    cb = async (execCmd) => {
        let slotNo = parseInt(args[1]);
        let latchData = Buffer.from(args[2], 'hex');

        let res = await storeLatchData(execCmd, slotNo, latchData);

        if (res[0] === 0xE1 && res.length === 2) {
            if (res[1] === 0x08) {
                let existingData = Buffer.from(await getLatch(execCmd, slotNo), 'hex');

                if (existingData.compare(latchData) === 0) {
                    return {"success": true, "message": "Same data is already stored in this latch."};
                } else {
                    return {"success": false, "message": "Different data is already stored in this latch."};
                }
            } else {
                return {"success": false, "message": "Latch failed with error code: " + res.toString('hex')};
            }
        }

        if (res.length === 1) {
            return {"success": true, "message": "Latch data was written succesfully."};
        }
    };
} else if (args[0] === "pkeys") {
    cb = async (execCmd) => {
        return await readPublicKeys(execCmd);
    };
} else if (args[0] === "ndef") {
    cb = async (execCmd, readNdef) => {
        let obj = await readNdef();
        let out = {};
        Object.keys(obj).forEach((k) => {
            out[k] = obj[k];
        });
        return {"success": true, "dynamic": out};
    }
} else if (args[0] === "info") {
    cb = async (execCmd, readNdef) => {
        let {pkey1, pkey2, pkey3} = await readPublicKeys(execCmd);

        let payload = Buffer.from("0401", "hex");
        let res1 = await execCmd(payload);

        payload = Buffer.from("0402", "hex");
        let res2 = await execCmd(payload);

        let tagVersion = null;

        if (res1[0] !== res2[0]) {
            throw Error('Mismatched tag version!');
        }

        if (res1[0] === 0xC2) {
            tagVersion = 0xC2;
        } else if (res1[0] === 0xC3) {
            tagVersion = 0xC3;
        } else {
            throw Error(`Unknown tag version: 0x${res1[0].toString(16)}`);
        }

        let attestSig1 = res1.slice(2);
        let attestSig2 = res2.slice(2);

        let attestKeyObj1 = ATTEST_KEYS[res1[1]];
        let attestKeyObj2 = ATTEST_KEYS[res2[1]];

        if (!attestKeyObj1) {
            throw Error('Failed to find attestation key #' + res1[1]);
        }

        if (!attestKeyObj2) {
            throw Error('Failed to find attestation key #' + res2[1]);
        }

        let key1 = ec.keyFromPublic(attestKeyObj1.publicKey, 'hex');
        let key2 = ec.keyFromPublic(attestKeyObj2.publicKey, 'hex');

        // check if tag's public keys are correctly signed with vendor's public key
        if (!key1.verify(sha256(Buffer.from(pkey1, 'hex')), attestSig1)) {
            throw Error('Attest verification failed!');
        }

        if (!key2.verify(sha256(Buffer.from(pkey2, 'hex')), attestSig2)) {
            throw Error('Attest verification failed!');
        }

        // check if this tag is really in the possession of its keys
        let challengePkey1 = randomBytes(32);
        let challengePkey2 = randomBytes(32);
        let challengePkey3 = randomBytes(32);

        let counter = null;

        let checkPkey1 = await signChallenge(execCmd, 1, challengePkey1);
        let checkPkey2 = null;

        if (tagVersion === 0xC2) {
            checkPkey2 = await signChallenge(execCmd, 2, challengePkey2);
        } else if (tagVersion === 0xC3) {
            let ndef = await readNdef();

            let cmdBuf = Buffer.from(ndef.cmd, 'hex');
            let resBuf = Buffer.from(ndef.res, 'hex');
            cmdBuf = cmdBuf.slice(2, 32 + 2);
            resBuf = resBuf.slice(0, resBuf[1] + 2);
            counter = cmdBuf.readUInt32BE(0);

            challengePkey2 = cmdBuf;
            checkPkey2 = resBuf;
        }

        let checkPkey3 = null;

        if (pkey3) {
            checkPkey3 = await signChallenge(execCmd, 3, challengePkey3);
        }

        let ecPkey1 = ec.keyFromPublic(pkey1, 'hex');
        let ecPkey2 = ec.keyFromPublic(pkey2, 'hex');
        let ecPkey3 = null;

        if (pkey3) {
            ecPkey3 = ec.keyFromPublic(pkey3, 'hex');
        }

        if (!ecPkey1.verify(challengePkey1, checkPkey1)) {
            throw Error('Failed to challenge public key #1');
        }

        if (!ecPkey2.verify(challengePkey2, checkPkey2)) {
            throw Error('Failed to challenge public key #2');
        }

        if (pkey3) {
            if (!ecPkey3 || !ecPkey3.verify(challengePkey3, checkPkey3)) {
                throw Error('Failed to challenge public key #3');
            }
        }

        // get latch values
        let latch1 = await getLatch(execCmd, 1);
        let latch2 = await getLatch(execCmd, 2);

        return {
            tagVersion: Buffer.from([res1[0]]).toString('hex'),
            issuer: attestKeyObj1,
            tagBuiltinKeys: {
                publicKey1: pkey1,
                publicKey2: pkey2,
                counterPk2: counter,
            },
            tagAdditionalKeys: {
                publicKey3: pkey3
            },
            latches: {
                latch1: latch1,
                latch2: latch2
            },
            attestSignature: attestSig1.toString('hex'),
            _: 'We have verified that the issuer signature is correct and the tag is able to sign data using these keys.'
        }
    };
} else if (args[0] === "keygen") {
    cb = async (execCmd) => {
        let payload = Buffer.from([0x03]);
        let res = await execCmd(payload);

        if (res[0] === 0xE1) {
            if (res[1] === 0x06) {
                return {'success': true, 'executed': false, 'message': 'Third key was already generated.'};
            } else {
                return {'success': false, 'executed': false, 'message': 'Failed to generate key. Error code: ' + res.toString('hex')};
            }
        }

        return {'success': true, 'executed': true, publicKey3: res.toString('hex')};
    };
} else {
    console.error('Usage:');
    console.error('');
    console.error('');
    console.error('    sign_raw <key_no> <digest>');
    console.error('    Perform ECDSA(digest) signature using NFC card.');
    console.error('    You must manually calculate hash of the data you want to sign.');
    console.error('    Any 32 byte long hash is accepted, especially the output of');
    console.error('    Etherum\'s Keccak-256(.), or classic SHA-256(.), or BLAKE-256(.)');
    console.error('');
    console.error('    Parameters:');
    console.error('        key_no - number of the key to use (from 1 to 3)');
    console.error('        digest - hex encoded 32 byte digest to sign directly');
    console.error('    Example invocation:');
    console.error('        sign 1 793d29ac53e8f8eda22fb298bf5d3df646aa8ca6dae5de3e20c086a4aa160827');
    console.error('');
    console.error('');
    console.error('    sign <key_no> <data>');
    console.error('    Perform ECDSA(Keccak-256(data)) signature using NFC card.');
    console.error('    The provided data is automatically hashed using Ethereum\'s');
    console.error('    Keccak-256(.) before actually executing the operation.');
    console.error('');
    console.error('    Parameters:');
    console.error('        key_no - number of the key to use (from 1 to 3)');
    console.error('        data - hex encoded data to sign');
    console.error('    Example invocation:');
    console.error('        sign 2 CAFEBABE1337');
    console.error('');
    console.error('');
    console.error('    pkeys');
    console.error('    Read public keys from the NFC tag.');
    console.error('');
    console.error('    No parameters.')
    console.error('');
    console.error('');
    console.error('    info');
    console.error('    Get all possible information about the NFC tag.');
    console.error('    This command will also fetch and validate the attestation');
    console.error('    signature.');
    console.error('');
    console.error('    No parameters.')
    console.error('');
    console.error('');
    console.error('    keygen');
    console.error('    Request the NFC tag to generate 3rd key.');
    console.error('');
    console.error('    No parameters.')
    console.error('');
    console.error('');
    console.error('    latch <latch_no> <data>');
    console.error('    Check if the signature is correct for given digest');
    console.error('    and whether it was really signed by the currently tapped NFC tag.');
    console.error('');
    console.error('    Parameters:');
    console.error('        latch_no - number of the latch to use (from 1 to 2)');
    console.error('        data - hex encoded, 32 bytes of the data to store');
    console.error('    Example invocation:');
    console.error('        latch 1 e5d961f8dad5f030f57e88e72aad26492d722afb5cc84256dca2ba6362bebf51');
    console.error('');
    process.exit(1);
}

function stopPCSC(code) {
    clearTimeout(timeout);

    if (code !== "done") {
        console.error(`NFC card or compatible PC/SC reader not found. Error code:  ${code}`);
    }

    for (let rdrName in nfc.readers) {
        nfc.readers[rdrName].close();
    }

    isClosing = true;
    nfc.close();
}

async function readNDEF(reader) {
    let resSelect = await reader.transmit(Buffer.from("00A4040007D276000085010100", "hex"), 255);

    if (resSelect.compare(Buffer.from([0x90, 0x00])) !== 0) {
        throw Error("Unable to select app");
    }

    let resSelectFile = await reader.transmit(Buffer.from("00A4000C02E10400", "hex"), 255);

    if (resSelectFile.compare(Buffer.from([0x90, 0x00])) !== 0) {
        throw Error("Unable to select NDEF file");
    }

    let readCmdBuf = Buffer.from("00B0000002", "hex");
    let resReadLength = await reader.transmit(readCmdBuf, 255);

    if (resReadLength.slice(-2).compare(Buffer.from([0x90, 0x00])) !== 0) {
        throw Error("Unable to read NDEF length");
    }

    let ndefLen = resReadLength.readUInt16BE(0) + 2;
    let offset = 0;

    let fullBuf = Buffer.alloc(0);

    while (ndefLen > 0) {
        readCmdBuf.writeUInt16BE(offset, 2);
        // ACR122U-A9 readers have a bug where they are returning 6F00 when Le is set to more than 0x3B
        // sounds like a firmware bug, because it can't be reproduced with other kinds of readers
        // (the same APDU is just working fine lol)
        readCmdBuf[4] = 0x30;

        let resReadNDEF = await reader.transmit(readCmdBuf, 255);

        if (resReadNDEF.slice(-2).compare(Buffer.from([0x90, 0x00])) !== 0) {
            throw Error("Unable to read NDEF file");
        }

        fullBuf = Buffer.concat([fullBuf, resReadNDEF.slice(0, -2)]);
        ndefLen -= 0x30;
        offset += 0x30;
    }

    fullBuf = fullBuf.slice(0, ndefLen);
    let qs = 'v=' + fullBuf.toString().split('?v=', 2)[1];
    return queryString.parse(qs);
}

async function executeCommand(reader, payload) {
    let resSelect = await reader.transmit(Buffer.from("00A4040007481199130e9f0100", "hex"), 255);

    if (resSelect.compare(Buffer.from([0x90, 0x00])) !== 0) {
        throw Error("Unable to select app");
    }

    const buf = Buffer.concat([
        Buffer.from("B0510000", "hex"),
        Buffer.from([payload.length]),
        payload,
        Buffer.from("00", "hex")
    ]);

    let startTime = new Date();
    let resCmd = await reader.transmit(buf, 255);
    let endTime = new Date();

    if (resCmd.slice(-2).compare(Buffer.from([0x90, 0x00])) !== 0) {
        throw Error("Command failed: " + resCmd.toString('hex'));
    }

    return resCmd.slice(0, -2);
}

nfc.on('reader', reader => {

    reader.autoProcessing = false;

    reader.on('card', async card => {

        clearTimeout(timeout);
        timeout = setTimeout(stopPCSC, 2000, "timeout");
        let res = null;

        try {
            res = await cb((payload) => executeCommand(reader, payload), () => readNDEF(reader));
        } catch (e) {
            console.error(e);
        }

        if (res !== null) {
            console.log(res);
            stopPCSC("done");
        }
    });

    reader.on('error', err => {
        console.log(`${reader.reader.name}  an error occurred`, err);
    });

});

nfc.on('error', err => {
    if (!isClosing) {
        console.log('an error occurred', err);
    }
});

timeout = setTimeout(stopPCSC, 2000, "timeout");
