function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
function publicKeyToJSON(res) {
  console.group('start check');
  const attestationObject = CBOR.decode(res.response.attestationObject);
  console.log('attestationObject: ', attestationObject);
  const clientDataJSON = JSON.parse(ab2str(res.response.clientDataJSON));
  console.log('clientDataJSON: ', clientDataJSON);
  const data = {
    id: res.id,
    type: res.type,
    rawId: ab2str(res.rawId),
    response: {
      clientDataJSON,
      attestationObject
    }
  };
  const authData = parseAuthData(attestationObject.authData);
  console.log('authData:', authData);
  const result = {
    fmt: attestationObject.fmt,
    credID: base64url.encode(authData.credID),
    aaguid: base64url.encode(authData.aaguid),
    publicKey: base64url.encode(authData.COSEPublicKey.buffer)
  };
  console.groupEnd('start check');
  console.log('data: ', data);

  return result;
}

function register(res) {
  const publicKey = Object.assign({}, res);

  publicKey.challenge = base64url.decode(publicKey.challenge);
  //publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), c=>c.charCodeAt(0));
  publicKey.user.id = base64url.decode(publicKey.user.id);

  navigator.credentials.create({ publicKey }).then(result => {
    console.log('register info: ', result);
    publicKeyToJSON(result)
    const otherInfo = publicKeyToJSON(result);
    const handle = publicKeyCredentialToJSON(result);
    console.log('send to server data: ', Object.assign(handle, otherInfo));
    return credentials(handle);
  }).catch(e => {
    console.log(e);
  })
}
function login(res) {
  const publicKey = Object.assign({}, res);
  publicKey.challenge = base64url.decode(publicKey.challenge);
  console.log('publicKey: ', publicKey);
  publicKey.allowCredentials[0].id = base64url.decode(publicKey.allowCredentials[0].id);

  navigator.credentials.get({ publicKey }).then(result => {
    console.log('login info: ', result);
    const handle = publicKeyCredentialToJSON(result);
    return fetch('/api/webauthn/assertion', {
      method: 'post',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(handle)
    }).then(res => res.json())
  }).then(res => {
    console.log('login info: ', res)
  }).catch(e => {
    console.error(e);
  })
}
function credentials(publicKey) {
  return fetch('/api/webauthn/credential', {
    method: 'post',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(publicKey)
  }).then(res => res.json()).then(res => {
    if (res.code !== 0) {
      if (isRegsiter) {
        alert('register success');
      } else {
        alert('login success');
      }
    }
  })
}

// btns
const register_btn = document.querySelector('#register_btn');
const login_btn = document.querySelector('#login_btn');
const action_btn = document.querySelector('#action_btn');

// field
const login_field = document.querySelector('#login_field');
const register_field = document.querySelector('#register_field');

// input
const login_name = document.querySelector('#login_name');
const register_name = document.querySelector('#register_name');

// status
let isRegsiter = true;

register_btn.addEventListener('click', function(e) {
  register_field.style.display = 'block';
  login_field.style.display = 'none';
  action_btn.innerText = '注册';
  isRegsiter = true;
});
login_btn.addEventListener('click', function(e) {
  register_field.style.display = 'none';
  login_field.style.display = 'block';
  action_btn.innerText = '登录';
  isRegsiter = false;
});

action_btn.addEventListener('click', function(e) {
  e.preventDefault();
  if (isRegsiter && register_name.value.length < 4) {
    alert('用户名长度必须大于4');
    return;
  }
  if (!isRegsiter && login_name.value.length < 4) {
    alert('用户名长度必须大于4');
    return;
  }
  if (isRegsiter) {
    fetch('/api/webauthn/register', {
      method: 'post',
      cache: 'no-cache',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: register_name.value
      })
    }).then(res => res.json()).then(res => {
      console.log('register params: ', res);
      register(res);
    })
  } else {
    fetch('/api/webauthn/login', {
      method: 'post',
      cache: 'no-cache',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: login_name.value
      })
    }).then(res => res.json()).then(res => {
      console.log('login params: ', res);
      login(res);
    })
  }
})

// check brower
if (!window.PublicKeyCredential) {
  alert('您的浏览并不支持WebAuthn, 请更换最新版的Chrome,Firefox');
}
