const express = require('express');
const router = express.Router();
const cryptoRandomString = require('crypto-random-string');
const verifyPackedAttestation = require('../utils/webauthn-packed.js');
const verifyAndroidSafetyNet = require('../utils/webauthn-android-safetynet.js');
const utils = require('../utils/utils.js');
const { decode } = require('base64url');
const crypto = require('crypto');

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
function registerUser(id, body) {
	const key = Object.keys(users).find(key => users[key].id === id);
  users[key] = Object.assign({}, users[key], {
    registered: true,
    credID: body.credID,
    counter: body.counter,
    publicKey: body.publicKey
  });
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

router.post('/assertion', (req, res, next) => {
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
  // todo
  try {
    const result = utils.verifyAuthenticatorAssertionResponse(body, users[name]);
    res.send({
      message: "login success",
      code: 0
    })
  } catch(err) {
    res.send({
      message: err.toString(),
      code: 1
    });
  }
})

router.post('/credential', (req, res, next) => {
  const body = req.body;
  if (!body) {
    res.send({
      message: 'params fail',
      code: 0
    })
    return;
  }
  const clientData = JSON.parse(decode(body.response.clientDataJSON));
  //console.log('clientData: ', clientData);
  if (req.cookies.challenge !== clientData.challenge) {
    res.send({
      message: 'challenge vaild fail',
      code: 0
    });
    return;
  }
  if (clientData.origin !== 'https://web.quietboy.net') {
    res.send({
      message: 'origin don\'t match',
      code: 0
    });
    return;
  }

  let result = false;
  let message = 'register faile';
  switch(body.fmt) {
    case 'android-safetynet':
      result = verifyAndroidSafetyNet(body);
      break;
    default:
      message = `server don\'t support${body.fmt}`;
  }
  console.log('verify register status: ', result);
  result && registerUser(req.cookies.id, body);
  res.clearCookie('challenge');
  res.send({
    message: result ? 'register in success' : message,
    code: 1
  });
})

router.get('/_admin_get_all_users', (req, res, next) => {
  res.send(users);
})

module.exports = router;
