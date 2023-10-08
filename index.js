//Setup Chalk
const chalk = require('chalk');

//Consume ENV
//require('dotenv').config({ path: `.env.${process.env.NODE_ENV}` });
require('dotenv').config({ path: `.env.development` });

//Require Crypto
const crypto = require('crypto');

//Setup Express
const express = require('express');
const app = express();
const port = 80;

app.use((req, res, next) => {
	const allowedOrigins = ["http://localhost:3000", "http://localhost:5000", "https://localhost:3000", "https://exilirate.com"];
	const origin = req.headers.origin;
	if (allowedOrigins.includes(origin)) {
		 res.setHeader('Access-Control-Allow-Origin', origin);
	}

	res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
	res.header('Access-Control-Allow-Credentials', true);
	return next();
});

//Get MongoDB connection string
const dbHost = process.env.DBHOST;
if(dbHost == undefined) {
	console.error(chalk.red("MongoDB Connection String Undefined"));
	process.exit(1);
}
//Connect To MongoDB
const { MongoClient, ServerApiVersion } = require("mongodb");
const mongo = new MongoClient(dbHost,  {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true,
	}
});

//Import Ethers
const ethers = require("ethers");

//Import JWT
const jwt = require("jsonwebtoken");
const jwtSecret = process.env.JWTSECRET;

//Welcome Statement
app.all('/', (req, res) => {
	res.status(405).send("Welcome to Exilirate Auth Server.");
});

//Gets the nonce to be signed
//Also works as a registration function if user does not yet exist
app.post('/getNonce', async (req, res) => {
	const address = req.query.address;
	
	//Check if publicKey is a valid Ethereum address
	if(ethers.utils.isAddress(address)) {
		//Push public key and nonce to DB
		const accountInfo = await mongo.db("exilirate").collection("users").findOne({"eAddr" : address});

		if(accountInfo == null){
			const newUserDoc = {
				eAddr : address,
				username : address,
				roles: ['user'],
				name : "Anonymous",
				bio : "",
				pfp : "",
				nonce : "" 
			};
			await mongo.db("exilirate").collection("users").insertOne(newUserDoc);
		}

		//Generate nonce using crypto lib
		const nonce = crypto.randomUUID();

		//Set nonce in MongoDB
		await mongo.db("exilirate").collection("users").updateOne(
			{
				"eAddr" : address
			},{ 
				$set: { 
					nonce: nonce
				}
			}
		);

		//Return nonce to user
		res.status(200).json({nonce: nonce, msg: "Success"});
	} else {
		//Error if public key is invalid
		res.status(400).json({nonce: null, msg: "Invalid Request: Invalid Public Key"});
	}
});

//Login using signed nonce and ethereum public key
app.post('/login', async (req, res) => {
	//Get needed data for signature verification
	const address = req.query.address;
	const nonce = req.query.nonce;
	const signature = req.query.signature;
	//Check validity of public ethereum address
	if(ethers.utils.isAddress(address)) {
		//Get nonce from DB to ensure registration
		const mongoDoc = await mongo.db("exilirate").collection("users").findOne({"eAddr" : address});
		const storedNonce = mongoDoc.nonce
		console.log("storedNonce: " + storedNonce);

		//Ensure user didn't sign arbitrary nonce
		if((nonce == storedNonce) && (nonce != undefined)) {
			//Validate signature
			const valid = await verifyMessage(address, nonce, signature);
			if(valid){
				const roles = mongoDoc.roles;
				console.log("roles: " + roles);
				//Sign JWT
				const token = jwt.sign({
					address: address,
					roles: roles,
				}, jwtSecret, {expiresIn: "2h"})

				//Return JWT to user
				res.status(200).json({JWT: token, msg: "Success"});
			} else {
				//Error if signature is invalid
				res.status(400).json({JWT: null, msg: "Invalid Request: Invalid Signature"});
			}
		} else {
			//Error if nonce is invalid
			res.status(400).json({JWT: null, msg: "Invalid Request: Invalid Nonce"});
		}
	} else {
		//Error if public key is invalid
		res.status(400).json({JWT: null, msg: "Invalid Request: Invalid Public Key"});
	}
});


//Verify if signature is valid with additional error catching
const verifyMessage = async (address, nonce, signature) => {
	try {
		const address = await ethers.utils.verifyMessage(nonce, signature);
		if (address !== address) {
			return false;
		}
		return true;
	} catch (error) {
		console.log(error);
		return false;
	}
};

//Error Catching Startup that is contingent on DB connection
const start = async () => {
	try {
		//Connect to mongo
		await mongo.connect();
		//Ping admin database to check connection
		await mongo.db("admin").command({ ping: 1 });
		app.listen(4000, () => console.log(chalk.green(`Exilirate Auth Server is listening on port ${port}`)));
	} catch (error) {
		await mongo.close();
		console.error(error);
		process.exit(1);
	}
};

//Start Auth Server
start();