const { NFC } = require('nfc-pcsc');

const nfc = new NFC();
let cb = null;
let timeout = null;
let isClosing = false;
let args = process.argv.slice(2);

if (args[0] === "sign") {
    cb = async (execCmd) => {
        let keyNo = parseInt(args[1]);
        let signData = args[2];

        let payload = Buffer.concat([
            Buffer.from([0x01, keyNo]),
            Buffer.from(signData, "hex")
        ]);

        let res = await execCmd(payload);

        if (res[0] === 0xE1 && res.length === 2) {
            return {"error": res.toString('hex')};
        }

        return {"sig": res.toString('hex')};
    };
} else if (args[0] === "pkeys") {
    cb = async (execCmd) => {
        let payload = Buffer.from("02", "hex");
        let res = await execCmd(payload);

        let pkey1 = null;
        let pkey2 = null;
        let pkey3 = null;

        pkey1 = res.slice(1, res[0]).toString('hex');
        res = res.slice(1 + res[0]);

        pkey2 = res.slice(1, res[0]).toString('hex');
        res = res.slice(1 + res[0]);

        if (res.length > 0) {
            pkey3 = res.slice(1, res[0]).toString('hex');
            res = res.slice(1 + res[0]);
        }

        return {pkey1, pkey2, pkey3};
    };
} else {
    console.error('Usage:');
    console.error('---');
    console.error('Sign 32 bytes of data using given key:')
    console.error('$ node cli.js sign <key_no> <data>');
    console.error('Example:');
    console.error('$ node cli.js sign 1 139e33f550dfd817805425693f5a33a499fd6b153f8b7ee749fd71fb978debe1');
    console.error('---');
    console.error('Read out the public keys');
    console.error('$ node cli.js pkeys');
    process.exit(1);
}

function stopPCSC() {
    clearTimeout(timeout);

    for (let rdrName in nfc.readers) {
        nfc.readers[rdrName].close();
    }

    isClosing = true;
    nfc.close();
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

    let resCmd = await reader.transmit(buf, 255);

    if (resCmd.slice(-2).compare(Buffer.from([0x90, 0x00])) !== 0) {
        throw Error("Command failed");
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
            res = await cb((payload) => executeCommand(reader, payload));
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
