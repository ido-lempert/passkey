require('dotenv').config();

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const {Pool} = require("pg");
const crypto = require('crypto');

const pool = new Pool({
    user: process.env.DB_USERNAME,
    host: process.env.DB_HOSTNAME,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    ssl: process.env.DB_SSL ? process.env.DB_SSL : false,
});


const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const { isoBase64URL } = require('@simplewebauthn/server/helpers');

const {json} = require("body-parser");


const app = express();
const port = process.env.PORT || 3000;

const rpID = process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'
const expectedOrigin = process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000';
const rpName = process.env.SITE_NAME || 'Passkey example';


const users = [];
const credentials = [];

const auth = (req, res, next)=>{
    if (req.session.username) {
        next();
    } else {
        return res.sendStatus(403);
    }

}

app.use(express.static('public'));

app.use(session({
    store: new pgSession({
        pool,
        tableName: 'sessions', // Name of the table you created for sessions
    }),
    secret: 'Aa123456$%&@#$', // Replace with your secret key
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    },
}));

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/challenge', async (req, res) => {
    try {
        // Use SimpleWebAuthn's handy function to create a new authentication request.
        const options = await generateAuthenticationOptions({
            rpID: rpID,
            allowCredentials: [],
        });

        // Keep the challenge value in a session.
        req.session.challenge = options.challenge;

        return res.json(options)
    } catch (e) {
        console.error(e);

        return res.status(400).json({ error: e.message });
    }
});

app.post('/register', json(), async (req, res)=>{
    const uuid = isoBase64URL.fromBuffer(crypto.randomBytes(32));
    // const user = {
    //     id: isoBase64URL.fromBuffer(crypto.randomBytes(32)),
    //     username: req.body.username,
    //     password: req.body.password
    // };

    // Insert user to DB
    let user;
    try{
        const data = [req.body.username, req.body.password, uuid];
        const userResult = await pool.query('INSERT INTO users (username, password, uuid) VALUES ($1,$2, $3) RETURNING *', data);
        user = userResult.rows[0];
        req.session.user = {id: user.id, uuid: user.uuid, username: user.username };
        // const data = {msg: 'register success'};
        //
        // console.log(req.path, data, result.rows[0]);
        //
        // return res.json(data);
    } catch (e) {
        return res.sendStatus(500);
    }

    try {
        // Create `excludeCredentials` from a list of stored credentials.
        const excludeCredentials = [];
        const creds = credentials.filter(cred => cred.user_id === user.id);
        for (const cred of creds) {
            excludeCredentials.push({
                id: isoBase64URL.toBuffer(cred.id),
                type: 'public-key',
                transports: cred.transports,
            });
        }
        // Set `authenticatorSelection`.
        const authenticatorSelection = {
            authenticatorAttachment: 'platform',
            requireResidentKey: true
        }
        const attestationType = 'none';

        // Use SimpleWebAuthn's handy function to create registration options.
        const options = await generateRegistrationOptions({
            rpName: rpName,
            rpID: rpID,
            userID: user.uuid,
            userName: user.username,
            userDisplayName: user.displayName || user.username,
            // Prompt users for additional information about the authenticator.
            attestationType,
            // Prevent users from re-registering existing authenticators
            excludeCredentials,
            authenticatorSelection,
        });

        // Keep the challenge value in a session.
        req.session.challenge = options.challenge;

        // Respond with the registration options.
        return res.json(options);
    } catch (e) {
        return res.sendStatus(500);
    }

});

/**
 * Register a new passkey to the server.
 */
app.put('/register', json(), async (req, res) => {
    // Set expected values.
    const expectedChallenge = req.session.challenge;
    // const expectedOrigin = getOrigin(req.get('User-Agent'));
    // const expectedRPID = rpID;
    const credential = req.body;

    try {
        // Use SimpleWebAuthn's handy function to verify the registration request.
        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge,
            expectedOrigin,
            expectedRPID : rpID,
            requireUserVerification: false,
        });

        const { verified, registrationInfo } = verification;

        // If the verification failed, throw.
        if (!verified) {
            throw new Error('User verification failed.');
        }

        const { credentialPublicKey, credentialID } = registrationInfo;

        // Base64URL encode ArrayBuffers.
        const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);
        const base64CredentialID = isoBase64URL.fromBuffer(credentialID);

        const user = req.session.user;
        try{
            const data = [base64CredentialID, base64PublicKey, credential.response.transports || [], user.id];
            await pool.query('INSERT INTO user_credentials (id, public_key, transports, user_id) VALUES ($1, $2, $3, $4) RETURNING *', data);
        } catch (e) {
            return res.sendStatus(500);
        }

        // Store the registration result.
        // credentials.push({
        //     id: base64CredentialID,
        //     public_key: base64PublicKey,
        //     // name: req.useragent.platform,
        //     transports: credential.response.transports || [],
        //     // registered: (new Date()).getTime(),
        //     // last_used: null,
        //     user_id: user.id,
        // });

        // Delete the challenge from the session.
        delete req.session.challenge;
        delete req.session.user;

        req.session.username = user.username;

        // Respond with the user information.
        return res.json(user);
    } catch (e) {
        delete req.session.challenge;
        delete req.session.user;

        console.error(e);
        return res.status(400).send({ error: e.message });
    }
});

app.put('/signin', json(), async (req, res) => {
    // Set expected values.
    const credential = req.body;
    const expectedChallenge = req.session.challenge;
    // const expectedOrigin = getOrigin(req.get('User-Agent'));
    // const expectedRPID = process.env.HOSTNAME;

    try {
        const credResult = await pool.query('SELECT * FROM user_credentials WHERE id = $1', [credential.id]);
        const cred = credResult.rows[0];

        console.log('/signin *user_credentials*', cred);
        // Find the matching credential from the credential ID
        // const cred = credentials.find(cred => cred.id === credential.id);
        if (!cred) {
            throw new Error('Matching credential not found on the server. Try signing in with a password.');
        }

        // Find the matching user from the user ID contained in the credential.
        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [cred.user_id]);
        const user = userResult.rows[0];
        console.log('/signin *user*', user);
        // const user = users.find(user => user.id === cred.user_id);
        if (!user) {
            throw new Error('User not found.');
        }

        // Decode ArrayBuffers and construct an authenticator object.
        const authenticator = {
            credentialPublicKey: isoBase64URL.toBuffer(cred.public_key),
            credentialID: isoBase64URL.toBuffer(cred.id),
            transports: cred.transports,
        };

        // Use SimpleWebAuthn's handy function to verify the authentication request.
        const verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge,
            expectedOrigin,
            expectedRPID : rpID,
            authenticator,
            requireUserVerification: false,
        });

        const { verified, authenticationInfo } = verification;

        console.log('/signin *verified*', verified);
        // If the authentication failed, throw.
        if (!verified) {
            throw new Error('User verification failed.');
        }

        // Update the last used timestamp.
        cred.last_used = (new Date()).getTime();

        // Delete the challenge from the session.
        delete req.session.challenge;

        // Start a new session.
        req.session.username = user.username;

        return res.json(user);
    } catch (e) {
        delete req.session.challenge;

        console.error(e);
        return res.status(400).json({ error: e.message });
    }
});

app.get('/transactions', auth, (req, res)=>{
    res.json([
        {
            id: 777,
            amount: 400
        }
    ]);
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});