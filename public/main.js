const loggedUrl = '/transactions';

const base64url = {
    encode: function(buffer) {
        const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    },
    decode: function(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const binStr = window.atob(base64);
        const bin = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
            bin[i] = binStr.charCodeAt(i);
        }
        return bin.buffer;
    }
}

function submitForm(e){
    this.event.preventDefault();
    register(window.username.value, window.password.value).then(res => {
        if (res.ok) {
            window.location.href = loggedUrl;
        }
    });
}

async function register(username, password){
    if (!username || !password ) alert('ERROR');

    const data = {
        username: window.username.value,
        password: window.password.value
    };


    const registerResponse = await fetch('/register', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
    const options = await registerResponse.json();

    // Base64URL decode some values
    options.user.id = base64url.decode(options.user.id);
    options.challenge = base64url.decode(options.challenge);
    if (options.excludeCredentials) {
        for (let cred of options.excludeCredentials) {
            cred.id = base64url.decode(cred.id);
        }
    }

    // Use platform authenticator and discoverable credential
    options.authenticatorSelection = {
        authenticatorAttachment: 'platform',
        requireResidentKey: true
    }

    if (abortController) {
        abortController.abort({name: 'reAuthenticate'});
        abortController = null;
    }

    // Invoke WebAuthn create
    const cred = await navigator.credentials.create({
        publicKey: options,
    });

    const credential = {};
    credential.id = cred.id;
    // Base64URL encode `rawId`
    credential.rawId = base64url.encode(cred.rawId);
    credential.type = cred.type;

    // `authenticatorAttachment` in PublicKeyCredential is a new addition in WebAuthn L3
    if (cred.authenticatorAttachment) {
        credential.authenticatorAttachment = cred.authenticatorAttachment;
    }

    // Base64URL encode some values
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);

    // Obtain transports if they are available.
    const transports = cred.response.getTransports ? cred.response.getTransports() : [];

    credential.response = {
        clientDataJSON,
        attestationObject,
        transports
    };

    // Send the result to the server and return the promise.
    return await fetch('/register', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(credential)});
}

let abortController;
async function authenticate(conditional = false){
    // Fetch passkey request options from the server.
    const challengeResponse = await fetch('/challenge');
    const options = await challengeResponse.json();

    // Base64URL decode the challenge
    options.challenge = base64url.decode(options.challenge);

    // `allowCredentials` empty array invokes an account selector by discoverable credentials.
    options.allowCredentials = [];

    // To abort a WebAuthn call, instantiate an `AbortController`.
    abortController = new AbortController();

    // Invoke WebAuthn get
    const cred = await navigator.credentials.get({
        publicKey: options,
        signal: abortController.signal,
        // Request a conditional UI
        mediation: conditional ? 'conditional' : 'optional'
    });

    const credential = {};
    credential.id = cred.id;
    credential.type = cred.type;
    // Base64URL encode `rawId`
    credential.rawId = base64url.encode(cred.rawId);

    // Base64URL encode some values
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);

    credential.response = {
        clientDataJSON,
        authenticatorData,
        signature,
        userHandle,
    };

    // Send the result to the server and return the promise.
    return await fetch('/signin', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(credential)});
}

async function autoSignin(){
    // Feature detection: check if WebAuthn and conditional UI are supported.
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isConditionalMediationAvailable) {
        try {
            const cma= await PublicKeyCredential.isConditionalMediationAvailable();
            if (cma) {
                // If a conditional UI is supported, invoke the conditional `authenticate()` immediately.
                const user = await authenticate(true);
                if (user) {
                    window.location.href = loggedUrl;
                    // When the user is signed in, redirect to the home page.
                    // $('#username').value = user.username;
                    // loading.start();
                    // location.href = '/home';
                } else {
                    throw new Error('User not found.');
                }
            }
        } catch (e) {
            // loading.stop();
            console.error(e);
            // `NotAllowedError` indicates a user cancellation.
            if (e.name !== 'NotAllowedError' && e.name !== 'reAuthenticate') {
                alert(e.message);
            }
        }
    }
}

function init(){
    // getChallenge();
    autoSignin();
}

init();