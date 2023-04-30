const fetch = require('node-fetch');
const ephemeralKeysArray = []; // array to store ephemeral keys
const ethUtil = require('ethereumjs-util');
const servers = ['http://localhost:2000', 'http://localhost:3000', 'http://localhost:4000'];
const p = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
//const p = 115792089210356248762697446949407573530086143415290314195533631308867097853951;


function _lagrange_interpolate(x, x_s, y_s, p) {
    const k = x_s.length;
    console.log('k:', k);
    if (k !== new Set(x_s).size) {
      throw new Error("points must be distinct");
    }
  
    function PI(vals) {
      return vals.reduce((accum, v) => accum * v, 1);
    }
  
    function _divmod(a, b, p) {
      const q = Math.trunc(Number(a) / Number(b));
      const r = a % b;
      //return [(q + p) % p, (r + p) % p];
      return [(Number(q) + Number(p)) % Number(p), (Number(r) + Number(p)) % Number(p)];

    }
  
    const nums = [];
    const dens = [];
    for (let i = 0; i < k; i++) {
      const others = [...x_s];
      const cur = others.splice(i, 1)[0];
      nums.push(PI(others.map((o) => x - o)));
      dens.push(PI(others.map((o) => cur - o)));
    }
  
    const den = dens.reduce((accum, val) => accum * BigInt(val), 1n) % BigInt(p);
    console.log('den:', den);
    const num = nums
      .map((n, i) => _divmod(BigInt(n) * BigInt(den) * BigInt(y_s[i]) % BigInt(p), BigInt(dens[i]), BigInt(p))[0])
      //.map((n, i) => _divmod(BigInt(n) * den * y_s[i] % BigInt(p), BigInt(dens[i]), BigInt(p))[0])
      .reduce((accum, val) => accum + val, 0);
  
    //return (num % p + p) % p;
    return (BigInt(num) % BigInt(p) + BigInt(p)) % BigInt(p);

}
  
  
const postData = async () => {

    // TBD: iterate ephemeral keys
    for (let i = 0; i < servers.length; i++) {
        const serverUrl = servers[i];
       
        const response = await fetch(`${serverUrl}/ephemeralKey`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            }
        });
          
        const result = await response.json();
        const { kShare, index } = result;
        console.log('result',kShare, index, result);
    
        // add kShare and nonce to an object 
        const ephemeralKeys = {
            kShare: kShare,
            nodeIndex: index,
            server: serverUrl
        };
        
        // append ephemeralKeys to an array
        ephemeralKeysArray.push(ephemeralKeys);
        console.log(ephemeralKeysArray);
        console.log(kShare, index);

    }

    // Lagrange interpolate the kShares to get k
    const kShares = ephemeralKeysArray.map(({kShare}) => kShare);
    const nodeIndices = ephemeralKeysArray.map(({nodeIndex}) => nodeIndex);
    const k = _lagrange_interpolate(0, nodeIndices, kShares, p);
    console.log(`Calculated k: ${k}`);

    // Declare array for signatures
    const sigArray = [];

    // Loop through the ephemeralKeysArray and send back k and nonce to the server for each ephemeral key
    for (let i = 0; i < ephemeralKeysArray.length; i++) {
        const ephemeralKeys = ephemeralKeysArray[i];
        const { kShare, index } = ephemeralKeys;
        const kShares = ephemeralKeysArray.map(({kShare}) => kShare);
        const nodeIndices = ephemeralKeysArray.map(({nodeIndex}) => nodeIndex);
        console.log('index:', nodeIndices[i]);
        const data = { message: "your_message", k: k.toString(), kSet: kShares, ephemeralKeysArray: ephemeralKeysArray, kShare: kShares[i], index: nodeIndices[i], p: p.toString()};
        const partialSig = await fetch("http://localhost:4000/sign", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });
        const pSig = await partialSig.json();
        const sigObj = {index: i, pSig}
        sigArray.push(sigObj);
        console.log('pSig:', pSig);
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




