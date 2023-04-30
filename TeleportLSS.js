const bodyParser = require('body-parser');
const { PythonShell } = require('python-shell');
const fs = require("fs");
const args = require('minimist')(process.argv.slice(2));
const port = args.port || 4000;
const express = require('express');
var app = express();
const path = require('path');
const { spawn } = require('child_process');
const { execSync } = require('child_process');

// Fetch the Python path using the command "which python"
const pythonPath = execSync('which python').toString().trim();
//const pythonPath = '/Library/WebServer/Documents/MachineLearning/anaconda3/bin/python';
const mongoose = require('mongoose');
const { Schema } = mongoose;
const MongoClient = require('mongodb').MongoClient;
const url = 'mongodb://localhost:27017';
const dbName = 'myproject';
const index = args.index || 1; // default index is 1 if --index argument is not provided

// Get the current directory path
const scriptPath = path.dirname(require.main.filename);

mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });

// Define schemas
const ephemeralKeySchema = new Schema({
    kShare: String,
    nonce: Number,
});

const signedMessageSchema = new Schema({
    message: String,
    k: String,
    kSet: Array,
    kShare: String,
    signature: String,
});

// Create Mongoose models
const EphemeralKey = mongoose.model('EphemeralKey', ephemeralKeySchema);
const SignedMessage = mongoose.model('SignedMessage', signedMessageSchema);

var nonce = 0;
app.use(bodyParser.json());

function runPythonScript(scriptPath, options) {
    return new Promise((resolve, reject) => {
      PythonShell.run(scriptPath, options, (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      });
    });
  }

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
      .reduce((accum, val) => accum + val, 0);
  
    //return (num % p + p) % p;
    return (BigInt(num) % BigInt(p) + BigInt(p)) % BigInt(p);

}

app.post('/ephemeralKey', async (req, res) => {

    const options = {
        mode: 'text',
        pythonPath: pythonPath, // Replace with path to Python interpreter
        pythonOptions: ['-u'],
        scriptPath: scriptPath, // Replace with path to directory containing keyGen1.py
        args: ['generate_ephemeral_keys'],
      };
      
      try {
        const results = await runPythonScript('keyGen1.py', options);
        const kShare = results[0].trim();
      
        // increment nonce
        nonce += 1;
      
        // save kShare and nonce to a mongodb database
        const ephemeralKey = new EphemeralKey({
          kShare: kShare,
          nonce: nonce,
        });
      
        ephemeralKey.save((err, savedKey) => {
          if (err) {
            console.log(err);
            res.status(500).send('Error inserting document into MongoDB');
          } else {
            console.log("Document inserted successfully");
            console.log('k_share:', kShare, 'nonce:', nonce, 'index:', index);
            res.status(200).json({ kShare, index });
          }
        });
      } catch (err) {
        console.error(err);
        res.status(500).send('Error generating ephemeral keys');
      }
      
    
});


app.post('/sign', async (req, res) => {
    const message = req.body.message;
    const k = req.body.k;
    const kSet = req.body.kSet;
    const kShare = req.body.kShare;
    const index = req.body.index;
    const p = req.body.p;
    const ephemeralKeysArray = req.body.ephemeralKeysArray;
  
    // Check that kShare is in the kSet
    const inKSet = kSet.includes(kShare);
    console.log('inKSet:', inKSet);
  
    // Exit out of the function if kShare is not in the kSet
    if (!inKSet) {
      res.status(500).send('kShare is not in the kSet');
      return;
    }
  
    try {

      // Look for kShare in the database collection
      const kShareResult = await EphemeralKey.find({ kShare: kShare }).exec();
      console.log("Document found successfully");
  
      if (kShareResult.length === 0) {
        console.log('kShare is not in the database');
        res.status(500).send('kShare is not in the database');
        return;

      } else {
        console.log(kShareResult);
        console.log('kShare is in the database');
  
        // Check if k is unique in the signedMessages collection
        const kResult = await SignedMessage.find({ k: k }).exec();
        console.log("Document found successfully");
  
        if (kResult.length == 0) {
            console.log('k is unique');


            try {
                let blindedPrivateKey = null;
                const x = 0; 
                const x_s = index; 
                const y_s = kShare;
    
                console.log('x:', x, 'x_s:', x_s, 'y_s:', y_s, 'p:', p, 'k:', k, 'kSet:', kSet, 'kShare:', kShare);
                

                const kShares = ephemeralKeysArray.map(({kShare}) => kShare);
                const nodeIndices = ephemeralKeysArray.map(({nodeIndex}) => nodeIndex);
                const result1 = _lagrange_interpolate(0, nodeIndices, kShares, p);
                console.log('result1:', result1, 'k:', k)
            
                  
                const lagrange_interpolate = result1;
                if (!result1 || !lagrange_interpolate) {
                    throw new Error('Could not interpolate kSet');
                }

                if (result1 == k) {
                    const options2 = {
                        mode: 'text',
                        pythonPath: pythonPath, // Replace with path to Python interpreter
                        pythonOptions: ['-u'],
                        scriptPath: scriptPath, // Replace with path to directory containing keyGen1.py
                        args: ['generate_keys'],
                    };
                      
                    try {
                        const [keysString] = await runPythonScript('keyGen1.py', options2);
                        const [privateKey, publicKey] = keysString.trim().split(',');
                        blindedPrivateKey = privateKey;
                        console.log('privateKey:', privateKey, 'publicKey:', publicKey, 'blindedPrivateKey:', blindedPrivateKey);
                    } catch (err) {
                        console.error(err);
                    }
                      
                    /*
                            from .ecdsa_python.ellipticcurve.ecdsa import Ecdsa
                        from .ecdsa_python.ellipticcurve.signature import Signature
                        from .ecdsa_python.ellipticcurve.hash import sha256
                        from .ecdsa_python.ellipticcurve.privateKey import PrivateKey
                        from .ecdsa_python.ellipticcurve.random import RandomInteger
                    */

                    const scriptString = `
                    
                        message = "${message}"
                        blindedPrivateKey = PrivateKey.fromString("${blindedPrivateKey}")
                        k = ${k}

                        signature = Ecdsa.signBlind(message, blindedPrivateKey, k, chain='ETH')

                        print(signature)
                    `;

                    console.log('scriptPath:', scriptPath);

                    const options3 = {
                        mode: 'text',
                        pythonPath: pythonPath,
                        pythonOptions: ['-u'],
                        scriptPath: scriptPath+'/ecdsa-python/ellipticcurve/',
                        args: ['-c', scriptString],
                    };

                    const result = await runPythonScript('ecdsa.py', options3);
                    const signature = result[0];
                    console.log('signature:', signature);

                    // Save signature to database
                    const client = await MongoClient.connect(url);
                    console.log("Connected successfully to mongoDB");

                    // Save signature to database
                    const db = client.db(dbName);
                    const collection = db.collection('signedMessages');
                    const doc = {
                        message: message,
                        k: k,
                        kSet: kSet,
                        kShare: kShare,
                        signature: signature
                    };

                    const result3 = await collection.insertOne(doc);
                    console.log("Document inserted successfully");
                    console.log('message:', message, 'k:', k, 'kSet:', kSet, 'kShare:', kShare, 'signature:', signature);
                    res.status(200).json({ message, k, kSet, kShare, signature });
                    client.close();

                }
            } catch (err) {
                throw err;
            }

        } else {
          console.log('k is not unique');
          res.status(500).send('k is not unique');
          mongoose.connection.close();
        }
      }
    } catch (err) {
      console.log(err);
      res.status(500).send('Error connecting to MongoDB');
    }
  });

  

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
