const express = require('express');
const router = express.Router();
const cryptoRandomString = require('crypto-random-string');
//const verifyPackedAttestation = require('../utils/webauthn-packed.js');
//const verifyAndroidSafetyNet = require('../utils/webauthn-android-safetynet.js');
//const utils = require('../utils/utils.js');
const { encode, decode, toBuffer } = require('base64url');
const base64url = require('../utils/array-buffer.js');
const crypto = require('crypto');
const AndroidSafetynet = require('../utils/android-safetynet.js');
const { Fido2Lib } = require('fido2-lib');

Fido2Lib.addAttestationFormat(
  AndroidSafetynet.name,
  AndroidSafetynet.parseFn,
  AndroidSafetynet.validateFn
)
const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: "web.quietboy.net",
  rpName: 'web.quietboy.net',
  challengeSize: 128,
  attestation: 'direct',
  cryptoParams: [-7 -257],
})
const users = {};
// { name: {registered: boolean, id: string, counter: number }}

function buildResData(name) {
	const res = {
		challenge: cryptoRandomString(100),
		id: cryptoRandomString(43),
	};

  if (users[name]) {
    return false;
  } else {
    users[name] = {
      registered: false,
      id: res.id,
      counter: 0
    }
  }
	return res;
}
function registerUser(id, obj) {
	const key = Object.keys(users).find(key => users[key].id === id);
  users[key] = Object.assign({}, users[key], {
    registered: true,
    ...obj
  });
}
function parseReqBodyWithArrayBuffer(body) {
  Object.keys(body).forEach(key => {
    if (typeof body[key] === 'object') {
      parseReqBodyWithArrayBuffer(body[key]);
    } else {
      body[key] = base64url.decode(body[key]);
    }
  })
}

router.post('/register', (req, res, next) => {
  const name = req.body.name;
  if (users[name] && users[name].registered) {
    res.send({
      message: `username ${name} is registered`,
      code: 0
    });
    return;
  }
	const resData = buildResData(name);
  console.log('register username: ', name);
	const result = {
	 status: 'ok',
	 errorMessage: '',
	 rp: {
	   name: 'web.quietboy.net',
	 },
	 user: {
	   name,
	   id: resData.id,
	   displayName: name,
	 },
	 challenge: resData.challenge,
	 pubKeyCredParams: [
	   {
		 type: 'public-key',
		 alg: -7,
	   },
	   {
		 type: 'public-key',
		 alg: -257,
	   },
	 ],
	 timeout: 60000,
	 attestation: 'direct',
	};
  res.cookie('challenge', result.challenge, { expires: new Date(Date.now() + 900000), httpOnly: true, secure: true })
  res.cookie('id', result.user.id , { expires: new Date(Date.now() + 900000), httpOnly: true, secure: true })
  res.send(result);
})

router.post('/login', (req, res, next) => {
  const name = req.body.name;
  if (!users[name] || !users[name].registered) {
    res.send({
      message: 'not register',
      code: 0
    });
    return;
  }
  console.log('login username: ', name);
  const challenge = cryptoRandomString(100);
	const result = {
	 status: 'ok',
	 errorMessage: '',
   challenge,
	 allowCredentials: [
	   { type: 'public-key', id: users[name].credID }
	 ],
	 timeout: 60000,
	};
  res.cookie('challenge', result.challenge, { expires: new Date(Date.now() + 900000), httpOnly: true, secure: true })
  res.send(result);
})

// assertion
router.post('/assertion', async (req, res, next) => {
  const body = req.body;
  const id = req.cookies.id;
  const name = Object.keys(users).find(key => users[key].id === id);
  if (!users[name]) {
    res.send({
      message: 'user not vaild',
      code: 0
    });
    return;
  }
  console.log(name, users[name])
  let result = null;
  try {
    result = await f2l.attestationResult(req.body, Object.assign(
      {}, users[name], {
        challenge: req.cookies.challenge,
        prevCounter: users[name].counter,
        factor: 'either',
        origin: 'https://web.quietboy.net'
      }
    ))
  } catch(err) {
    result = null;
  }
  console.log('username: ' + name + ' login status: ', result);
  if (result) {
    res.send({
      message: 'login success',
      code: 1
    })
  } else {
    res.send({
      message: 'login failed',
      code: 0
    })
  }
})

// attestation
router.post('/credential', async (req, res, next) => {
  const body = req.body;
  if (!body) {
    res.send({
      message: 'params fail',
      code: 0
    })
    return;
  }
  const attestation = {
    challenge: req.cookies.challenge,
    origin: 'https://web.quietboy.net',
    factor: 'either'
  }

  let message = 'register faile';
  let result = null;
  try {
    const body = req.body;
    parseReqBodyWithArrayBuffer(body);
    console.log(body.credID);

    result = await f2l.attestationResult(body, attestation);
    message = 'register success';
  } catch(err) {
    result = false;
    message = err;
  }

  console.log('verify register status: ', message);
  if (result) {
    registerUser(req.cookies.id, result);
    res.clearCookie('challenge');
  }
  res.send({
    message: message.toString(),
    code: result ? 1 : 0
  });
})

router.get('/_admin_get_all_users', (req, res, next) => {
  res.send(users);
})

module.exports = router;
