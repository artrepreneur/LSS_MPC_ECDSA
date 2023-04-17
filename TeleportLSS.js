const express = require('express');
const bodyParser = require('body-parser');
const { PythonShell } = require('python-shell');
const fs = require("fs");
//const port = process.argv[2] || 4000;
const args = require('minimist')(process.argv.slice(2));
const port = args.port || 4000;
var app = express();
const path = require('path');
const { execSync } = require('child_process');
// Fetch the Python path using the command "which python"
const pythonPath = execSync('which python').toString().trim();
//const pythonPath = '/Library/WebServer/Documents/MachineLearning/anaconda3/bin/python';
const mongoose = require('mongoose');
const { Schema } = mongoose;
const MongoClient = require('mongodb').MongoClient;
const url = 'mongodb://localhost:27017';
const dbName = 'myproject';

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

app.post('/ephemeralKey', (req, res) => {
    PythonShell.runString(`
        from ellipticcurve.utils.integer import RandomInteger

        def generate_ephemeral_keys():
            k_share = RandomInteger.between(1, curve.N - 1)
            return k_share

        result = generate_ephemeral_keys()
        print(result)
    `, null, (err, result) => {
        if (err) {
        console.log(err);
        res.status(500).send('Error generating ephemeral keys');
        } else {
        const kShare = result[0].trim();

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
            console.log('k_share:', kShare, 'nonce:', nonce);
            res.status(200).json({ kShare, nonce });
            }
        });
        }
    });
});





app.post('/sign', async (req, res) => {
    const message = req.body.message;
    const k = req.body.k;
    const kSet = req.body.kSet;
    const kShare = req.body.kShare;
  
    // Check that kShare is in the kSet
    const inKSet = kSet.includes(kShare);
    console.log('inKSet:', inKSet);
  
    // exit out of the function if kShare is not in the kSet
    if (!inKSet) {
      res.status(500).send('kShare is not in the kSet');
      return;
    }
  
    try {
      await mongoose.connect(url);
      console.log("Connected successfully to server");
  
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
            // Check that interpolate of kSet is k using a call to python
            const options1 = {
                mode: 'text',
                pythonPath: pythonPath, // replace with the path to your Python executable
                pythonOptions: ['-u'], // get print results in real-time
                scriptPath: './lagrangeInterpolate.py', // replace with the path to the directory containing your Python script
            };

            const x = kSet.x;
            const x_s = kSet.x_s;
            const y_s = kSet.y_s;
            const p = kSet.prime;

            try {
                const result1 = await PythonShell.runPromise('lagrangeInterpolate.py', options1);
                const lagrange_interpolate = result1[0];
                const result2 = lagrange_interpolate(x, x_s, y_s, p);
                console.log('result:', result2, 'k:', k);

                if (result2 == k) {
                    // Call keyGen1.py to generate private and public keys
                    const options2 = {
                        mode: 'text',
                        pythonPath: pythonPath, // Replace with path to Python interpreter
                        pythonOptions: ['-u'],
                        scriptPath: './keyGen1.py', // Replace with path to directory containing keyGen1.py
                    };

                    const result3 = await PythonShell.runPromise('keyGen1.py', options2);
                    const privateKey = result3[0];
                    const publicKey = result3[1];
                    let blindedPrivateKey = privateKey;
                    console.log('privateKey:', privateKey, 'publicKey:', publicKey);

                    // Call signBlind function from ecdsa.py
                    const options3 = {
                        mode: 'text',
                        pythonPath: pythonPath, // Replace with path to Python interpreter
                        pythonOptions: ['-u'],
                        scriptPath: './ecdsa.py', // Replace with path to directory containing ecdsa.py
                        args: [message, blindedPrivateKey, k]
                    };

                    const scriptString = `
                        from ecdsa import Ecdsa
                        from hashlib import sha256
                        from crypto.libs.privateKey import PrivateKey
                        from crypto.libs.random import RandomInteger

                        message = "${message}"
                        blindedPrivateKey = PrivateKey.fromString("${blindedPrivateKey}")
                        k = ${k}

                        signature = Ecdsa.signBlind(message, blindedPrivateKey, k, chain='ETH')

                        print(signature)
                    `;

                    const signature = await PythonShell.runStringPromise(scriptString, options3);
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

                    const result5 = await collection.insertOne(doc);
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
