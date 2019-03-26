const express = require('express');
const router = express.Router();
const cryptoRandomString = require('crypto-random-string');
const verifyPackedAttestation = require('../utils/webauthn');

const users = [];

function buildResData(name) {
	const res = {
		challenge: cryptoRandomString(100),
		id: cryptoRandomString(43),
	};
	const hasIndex = users.findIndex(item => item.name === name);
  if (hasIndex > -1) {
    users[hasIndex] = Object.assign(
      {}, users[hasIndex], res,
    );
  } else {
    users.push({
      name,
      ...res,
    });
  }
	return res;
}
function getResData(name) {
  const res = {
		challenge: cryptoRandomString(100),
	};
  const hasIndex = users.findIndex(item => item.name === name);
  if (hasIndex > -1) {
    users[hasIndex] = Object.assign(
      {}, users[hasIndex], res,
    );
    return res;
  }
  return {
    message: 'not register',
    code: 0
  }
}


router.post('/register', (req, res, next) => {
  const name = req.body.name;
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
  res.send(result);
})

router.post('/login', (req, res, next) => {
  const name = req.body.name;
	const resData = getResData(name);
  console.log('login username: ', name);
	const result = {
	 status: 'ok',
	 errorMessage: '',
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
  res.send(result);
})

router.post('/attestation', (req, res, next) => {
  if (!req.body) {
    res.send({
      message: 'params fail',
      code: 0
    })
    return;
  }

  const result = verifyPackedAttestation(req.body);
  console.log(result);
  return result;
})

router.get('/_admin_get_all_users', (req, res, next) => {
  res.send(users);
})

module.exports = router;
