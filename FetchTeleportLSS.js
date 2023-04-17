const fetch = require('node-fetch');
const ephemeralKeysArray = []; // array to store ephemeral keys
const ethUtil = require('ethereumjs-util');
const servers = ['http://localhost:3000', 'http://localhost:4000', 'http://localhost:5000'];


const postData = async () => {

    // TBD: iterate ephemeral keys
    for (let i = 0; i < servers.length; i++) {
        const serverUrl = servers[i];
        const response = await fetch(`${serverUrl}/ephemeralKey`, {
          method: "POST",
          headers: {
              "Content-Type": "application/json"
          },
          body: JSON.stringify(data)
        });
    
        const result = await response.json();
        const { kShare, nonce } = result;
    
        // add kShare and nonce to an object 
        const ephemeralKeys = {
            kShare: kShare,
            nonce: nonce,
            server: serverUrl
        };
        
        // append ephemeralKeys to an array
        ephemeralKeysArray.push(ephemeralKeys);
        console.log(ephemeralKeysArray);
        console.log(kShare, nonce);
    }

    // Lagrange interpolate the kShares to get k
    const kShares = ephemeralKeysArray.map(({kShare}) => kShare);
    const nonces = ephemeralKeysArray.map(({nonce}) => nonce);
    const k = _lagrange_interpolate(0, nonces, kShares, p);
    console.log(`Calculated k: ${k}`);

    // Send back k, and nonce to the server
    const data = { message: "your_message", k: k.toString(), kSet: kShares, kShare: "1234" };
    const response2 = await fetch("http://localhost:4000/sign", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const result2 = await response2.json();
    console.log(result2);


    // Declare array for signatures
    const sigArray = [];

    // Loop through the ephemeralKeysArray and send back k and nonce to the server for each ephemeral key
    for (let i = 0; i < ephemeralKeysArray.length; i++) {
        const ephemeralKeys = ephemeralKeysArray[i];
        const { kShare, nonce } = ephemeralKeys;
        const kShares = ephemeralKeysArray.map(({kShare}) => kShare);
        const nonces = ephemeralKeysArray.map(({nonce}) => nonce);
        const data = { message: "your_message", k: k.toString(), kSet: kShares, kShare: kShares[i] };
        const partialSig = await fetch("http://localhost:4000/sign", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });
        const partialSig = await partialSig.json();
        const sigObj = {index: i, partialSig}
        sigArray.push(sigObj);
        console.log('partialSig:', partialSig);
    }

    // Interpolate the signatures to get the final signature
    const partialSig = sigArray.map(({partialSig}) => partialSig);
    const index = sigArray.map(({index}) => index);
    const sig = _lagrange_interpolate(0, index, partialSig, p);
    console.log(`Calculated sig: ${sig}`);

    // Check the final signature against the message and public key
    const partialSigR = sigArray.map(({ partialSig }) => partialSig.r);
    const partialSigS = sigArray.map(({ partialSig }) => partialSig.s);
    const partialSigRid = sigArray.map(({ partialSig }) => partialSig.recoveryId);

    const interpolatedR = _lagrange_interpolate(0, partialSigR, p);
    const interpolatedS = _lagrange_interpolate(0, partialSigS, p);

    let recoveryId = 0;

    if (interpolatedR > p / 2) {
    recoveryId = recoveryId + 1;
    }
    if (interpolatedS > p / 2) {
    recoveryId = recoveryId + 2;
    }

    const hexR = ethUtil.bufferToHex(ethUtil.toBuffer(interpolatedR));
    const hexS = ethUtil.bufferToHex(ethUtil.toBuffer(interpolatedS));
    const hexV = ethUtil.bufferToHex(ethUtil.toBuffer(27 + recoveryId % 2));

    const signature = hexR + hexS.slice(2) + hexV.slice(2);
    const messageHash = ethUtil.keccak(Buffer.from("your_message", "utf8"));

    const recoveredAddress = ethUtil.ecrecover(messageHash, 27 + recoveryId % 2, ethUtil.toBuffer(hexR), ethUtil.toBuffer(hexS));
    const publicKeyBuffer = ethUtil.publicToAddress(recoveredAddress);
    const recoveredPublicKey = ethUtil.bufferToHex(publicKeyBuffer);

    console.log('recoveredPublicKey:', recoveredPublicKey);

    // Replace 'your_public_key' with the actual public key
    if (recoveredPublicKey.toLowerCase() === 'your_public_key'.toLowerCase()) {
        console.log('Signature is valid');
    } else {
        console.log('Signature is invalid');
    }



}

postData();




