[![Build Status](https://travis-ci.org/erdtman/cwt-js.svg?branch=master)](https://travis-ci.org/erdtman/cwt-js)
[![Coverage Status](https://coveralls.io/repos/github/erdtman/cwt-js/badge.svg?branch=master)](https://coveralls.io/github/erdtman/cwt-js?branch=master)

# cwt-js
[CWT](https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token) implementation.

# install
```
npm install cwt-js --save
```
# Usage
# MAC CWT
```js
const CWT = require('cwt-js');

const encKey = Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex');
const alg = 'HS256/64';
const kid = 'Symmetric256';
const claims = {
  'iss': 'coap://as.example.com',
  'sub': 'erikw',
  'aud': 'coap://light.example.com',
  'exp': 1444064944,
  'nbf': 1443944944,
  'iat': 1443944944,
  'cti': '0b71'
};

const cwt = CWT.create(claims);
cwt.mac(encKey, alg, kid).then(output => {
  console.log(output.toString('hex'));
});
```
# Verify MAC CWT
```js
const CWT = require('cwt-js');
const decKey = Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex');
const token = Buffer.from('d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200', 'hex');

CWT.read(token, decKey).then(claims => {
  console.log(claims);
});
```
