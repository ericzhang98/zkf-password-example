const nodecrypto = require('crypto');
const snarkjs = require("snarkjs");
const fs = require("fs");

async function run_division() {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({x1: 13, x2: 7, x3: 4, x4: 2}, "division.wasm", "division.zkey");

    console.log("Proof: ");
    console.log(JSON.stringify(proof, null, 1));
    console.log("Public signals: ")
    console.log(publicSignals);

    const vKey = JSON.parse(fs.readFileSync("division.vkey.json"));
    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
}

async function run_hash() {
    const password = "password";

    const hashedPassword = nodecrypto.createHash('sha256').update(password).digest('hex');
    console.log("hashed password:", hashedPassword);
    const hashedPasswordInt = parseInt(hashedPassword, 16);
    console.log("integer encoding: ", hashedPasswordInt)

    const { proof, publicSignals } = await snarkjs.groth16.fullProve({x: hashedPasswordInt}, "hash.wasm", "hash.zkey");

    console.log("Proof: ");
    console.log(JSON.stringify(proof, null, 1));
    console.log("Public signals: ")
    console.log(publicSignals);

    const vKey = JSON.parse(fs.readFileSync("hash.vkey.json"));
    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
}

run_hash().then(() => {
    process.exit(0);
});