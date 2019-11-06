/* eslint no-bitwise: 0 */
const sha256 = require('sha256');

const checklength = q => {
  if (q.length === 79) {
    return true;
  }
  return false;
};

const checkQ = q => {
  if (q.slice(0, 1) === 'Q') {
    return true;
  }
  return false;
};

function hexToBytes(hex) {
  const bytes = [];
  let c = 0;
  for (c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return bytes;
}

function byte2bits(a) {
  let tmp = '';
  let i = 128;
  for (i = 128; i >= 1; i /= 2) tmp += a & i ? '1' : '0';
  return tmp;
}
function split2Bits(a, n) {
  let buff = '';
  const b = [];
  let i = 0;
  for (i = 0; i < a.length; i += 1) {
    buff += byte2bits(a[i]);
    while (buff.length >= n) {
      b.push(buff.substr(0, n));
      buff = buff.substr(n);
    }
  }
  return [b, buff];
}

function toByteArray(input) {
  const result = [];
  let hs = input;
  while (hs.length >= 2) {
    result.push(parseInt(hs.substring(0, 2), 16));
    hs = hs.substring(2, hs.length);
  }
  return result;
}

function checkHash(q) {
  const qs = q.slice(1, 71);
  const qa = hexToBytes(q.slice(71, 80));
  const qx = sha256(hexToBytes(qs));
  const qm = qx.slice(56, 64);
  const qj = hexToBytes(qm);
  return (
    qj[0] === qa[0] && qj[1] === qa[1] && qj[2] === qa[2] && qj[3] === qa[3]
  );
}

function isMultisig(b) {
  let result = false;
  if (
    b[0].toString() === '0001'
    && b[1].toString() === '0001'
    && b[2].toString() === '0000'
    && b[3].toString() === '0000'
    && b[4].toString() === '0000'
    && b[5].toString() === '0000'
  ) { result = true; }
  return result;
}

function checkXMSS(q) {
  const debug = { hash: {}, sig: {} };
  let passed = 0;
  const qr = q.slice(1, 7);
  const a = toByteArray(qr);
  const b = split2Bits(a, 4)[0];
  // console.log('b0: ', b[0].toString());
  // console.log('b1: ', b[1].toString());
  // console.log('b2: ', b[2].toString());
  // console.log('b3: ', b[3].toString());
  // console.log('b4: ', b[4].toString());
  // console.log('b5: ', b[5].toString());
  // first check in multisig
  if (isMultisig(b)) {
    return {
      result: true,
      sig: {
        type: 'MULTISIG',
        result: true,
        message: 'valid signature scheme',
        height: 0,
        number: 0,
      },
      hash: {
        message: 'valid HASH mechanism',
        result: true,
        function: 'SHA2-256',
      },
    };
  }
  if (
    b[1].toString() === '0000'
    || b[1].toString() === '0001'
    || b[1].toString() === '0010'
  ) {
    debug.hash.message = 'valid HASH mechanism';
    debug.hash.result = true;
    passed += 1;
    if (b[1].toString() === '0000') {
      debug.hash.function = 'SHA2-256';
    }
    if (b[1].toString() === '0001') {
      debug.hash.function = 'SHAKE-128';
    }
    if (b[1].toString() === '0010') {
      debug.hash.function = 'SHAKE-256';
    }
  } else {
    debug.hash.message = 'invalid HASH mechanism';
    debug.hash.result = false;
  }
  if (b[0].toString() === '0000') {
    debug.sig.message = 'valid signature scheme';
    debug.sig.result = true;
    debug.sig.type = 'XMSS';
    let height = parseInt(b[3], 2);
    height *= 2;
    debug.sig.height = height;
    debug.sig.number = Math.pow(2, height); // eslint-disable-line
    passed += 1;
  } else {
    debug.sig.message = 'invalid signature scheme';
    debug.sig.result = false;
  }
  if (passed === 2) {
    debug.result = true;
  } else {
    debug.result = false;
  }
  return debug;
}

function hexString(q) {
  let passed = 0;
  const debug = {
    len: {},
    startQ: {},
    signature: {},
    checksum: {},
    hash: {},
    sig: {},
  };

  if (checklength(q)) {
    debug.len.message = 'length ok';
    debug.len.result = true;
    passed += 1;
  } else {
    debug.len.message = 'length bad';
    debug.len.result = false;
  }

  if (checkQ(q)) {
    debug.startQ.message = 'starts with Q ok';
    debug.startQ.result = true;
    passed += 1;
  } else {
    debug.startQ.message = 'does not start with Q';
    debug.startQ.result = false;
  }

  if (debug.len.result === false) {
    debug.sig.message = 'invalid signature scheme';
    debug.sig.result = false;
  } else {
    const hashSig = checkXMSS(q);
    debug.signature.message = `${hashSig.hash.message} / ${hashSig.sig.message}`;
    debug.sig.message = hashSig.sig.message;
    debug.sig.result = hashSig.sig.result;
    debug.hash.result = hashSig.hash.result;
    debug.hash.message = hashSig.hash.message;
    debug.hash.function = hashSig.hash.function;
    debug.sig.height = hashSig.sig.height;
    debug.sig.number = hashSig.sig.number;
    debug.sig.type = hashSig.sig.type;
    if (hashSig.result) {
      debug.signature.result = true;
      passed += 1;
    } else {
      debug.signature.result = false;
    }
    if (checkHash(q)) {
      debug.checksum.message = 'checksum ok';
      debug.checksum.result = true;
      passed += 1;
    } else {
      debug.checksum.message = 'bad address checksum';
      debug.checksum.result = false;
    }
  }

  if (passed === 4) {
    debug.result = true;
  } else {
    debug.result = false;
  }
  return debug;
}

module.exports = {
  /**
   * Reports the current module version
   * @return {string} version
   */
  version() {
    return '3.0.0';
  },
  hexString(q) {
    if (q === undefined) {
      return { result: false, error: 'Missing parameter' };
    }
    return hexString(q);
  },
};
