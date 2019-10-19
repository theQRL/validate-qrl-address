(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.validateQrlAddress = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
!function(globals) {
'use strict'

var convertHex = {
  bytesToHex: function(bytes) {
    /*if (typeof bytes.byteLength != 'undefined') {
      var newBytes = []

      if (typeof bytes.buffer != 'undefined')
        bytes = new DataView(bytes.buffer)
      else
        bytes = new DataView(bytes)

      for (var i = 0; i < bytes.byteLength; ++i) {
        newBytes.push(bytes.getUint8(i))
      }
      bytes = newBytes
    }*/
    return arrBytesToHex(bytes)
  },
  hexToBytes: function(hex) {
    if (hex.length % 2 === 1) throw new Error("hexToBytes can't have a string with an odd number of characters.")
    if (hex.indexOf('0x') === 0) hex = hex.slice(2)
    return hex.match(/../g).map(function(x) { return parseInt(x,16) })
  }
}


// PRIVATE

function arrBytesToHex(bytes) {
  return bytes.map(function(x) { return padLeft(x.toString(16),2) }).join('')
}

function padLeft(orig, len) {
  if (orig.length > len) return orig
  return Array(len - orig.length + 1).join('0') + orig
}


if (typeof module !== 'undefined' && module.exports) { //CommonJS
  module.exports = convertHex
} else {
  globals.convertHex = convertHex
}

}(this);
},{}],2:[function(require,module,exports){
!function(globals) {
'use strict'

var convertString = {
  bytesToString: function(bytes) {
    return bytes.map(function(x){ return String.fromCharCode(x) }).join('')
  },
  stringToBytes: function(str) {
    return str.split('').map(function(x) { return x.charCodeAt(0) })
  }
}

//http://hossa.in/2012/07/20/utf-8-in-javascript.html
convertString.UTF8 = {
   bytesToString: function(bytes) {
    return decodeURIComponent(escape(convertString.bytesToString(bytes)))
  },
  stringToBytes: function(str) {
   return convertString.stringToBytes(unescape(encodeURIComponent(str)))
  }
}

if (typeof module !== 'undefined' && module.exports) { //CommonJS
  module.exports = convertString
} else {
  globals.convertString = convertString
}

}(this);
},{}],3:[function(require,module,exports){
!function(globals) {
'use strict'

var _imports = {}

if (typeof module !== 'undefined' && module.exports) { //CommonJS
  _imports.bytesToHex = require('convert-hex').bytesToHex
  _imports.convertString = require('convert-string')
  module.exports = sha256
} else {
  _imports.bytesToHex = globals.convertHex.bytesToHex
  _imports.convertString = globals.convertString
  globals.sha256 = sha256
}

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

// Initialization round constants tables
var K = []

// Compute constants
!function () {
  function isPrime(n) {
    var sqrtN = Math.sqrt(n);
    for (var factor = 2; factor <= sqrtN; factor++) {
      if (!(n % factor)) return false
    }

    return true
  }

  function getFractionalBits(n) {
    return ((n - (n | 0)) * 0x100000000) | 0
  }

  var n = 2
  var nPrime = 0
  while (nPrime < 64) {
    if (isPrime(n)) {
      K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3))
      nPrime++
    }

    n++
  }
}()

var bytesToWords = function (bytes) {
  var words = []
  for (var i = 0, b = 0; i < bytes.length; i++, b += 8) {
    words[b >>> 5] |= bytes[i] << (24 - b % 32)
  }
  return words
}

var wordsToBytes = function (words) {
  var bytes = []
  for (var b = 0; b < words.length * 32; b += 8) {
    bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF)
  }
  return bytes
}

// Reusable object
var W = []

var processBlock = function (H, M, offset) {
  // Working variables
  var a = H[0], b = H[1], c = H[2], d = H[3]
  var e = H[4], f = H[5], g = H[6], h = H[7]

    // Computation
  for (var i = 0; i < 64; i++) {
    if (i < 16) {
      W[i] = M[offset + i] | 0
    } else {
      var gamma0x = W[i - 15]
      var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
                    ((gamma0x << 14) | (gamma0x >>> 18)) ^
                    (gamma0x >>> 3)

      var gamma1x = W[i - 2];
      var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                    ((gamma1x << 13) | (gamma1x >>> 19)) ^
                    (gamma1x >>> 10)

      W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
    }

    var ch  = (e & f) ^ (~e & g);
    var maj = (a & b) ^ (a & c) ^ (b & c);

    var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
    var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

    var t1 = h + sigma1 + ch + K[i] + W[i];
    var t2 = sigma0 + maj;

    h = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }

  // Intermediate hash value
  H[0] = (H[0] + a) | 0;
  H[1] = (H[1] + b) | 0;
  H[2] = (H[2] + c) | 0;
  H[3] = (H[3] + d) | 0;
  H[4] = (H[4] + e) | 0;
  H[5] = (H[5] + f) | 0;
  H[6] = (H[6] + g) | 0;
  H[7] = (H[7] + h) | 0;
}

function sha256(message, options) {;
  if (message.constructor === String) {
    message = _imports.convertString.UTF8.stringToBytes(message);
  }

  var H =[ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
           0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ];

  var m = bytesToWords(message);
  var l = message.length * 8;

  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;

  for (var i=0 ; i<m.length; i += 16) {
    processBlock(H, m, i);
  }

  var digestbytes = wordsToBytes(H);
  return options && options.asBytes ? digestbytes :
         options && options.asString ? _imports.convertString.bytesToString(digestbytes) :
         _imports.bytesToHex(digestbytes)
}

sha256.x2 = function(message, options) {
  return sha256(sha256(message, { asBytes:true }), options)
}

}(this);

},{"convert-hex":1,"convert-string":2}],4:[function(require,module,exports){
const sha256 = require("sha256");

const checklength = q => {
  if (q.length === 79) {
    return true;
  }
  return false;
};

const checkQ = q => {
  if (q.slice(0, 1) === "Q") {
    return true;
  }
  return false;
};

function hexToBytes(hex) {
  for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

function byte2bits(a) {
  var tmp = "";
  for (var i = 128; i >= 1; i /= 2) tmp += a & i ? "1" : "0";
  return tmp;
}
function split2Bits(a, n) {
  var buff = "";
  var b = [];
  for (var i = 0; i < a.length; i++) {
    buff += byte2bits(a[i]);
    while (buff.length >= n) {
      b.push(buff.substr(0, n));
      buff = buff.substr(n);
    }
  }
  return [b, buff];
}

function toByteArray(hexString) {
  var result = [];
  while (hexString.length >= 2) {
    result.push(parseInt(hexString.substring(0, 2), 16));
    hexString = hexString.substring(2, hexString.length);
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

function checkXMSS (q) {
  const debug = { hash: {}, sig: {} };
  let passed = 0;
  const qr = q.slice(1, 7);
  const a = toByteArray(qr);
  const b = split2Bits(a, 4)[0];
  if (
    b[1].toString() === "0000" ||
    b[1].toString() === "0001" ||
    b[1].toString() === "0010"
  ) {
    debug.hash.message = "valid HASH mechanism";
    debug.hash.result = true;
    passed += 1;
    if (b[1].toString() === "0000") {
      debug.hash.function = "SHA2-256";
    }
    if (b[1].toString() === "0001") {
      debug.hash.function = "SHAKE-128";
    }
    if (b[1].toString() === "0010") {
      debug.hash.function = "SHAKE-256";
    }
  } else {
    debug.hash.message = "invalid HASH mechanism";
    debug.hash.result = false;
  }
  if (b[0].toString() === "0000") {
    debug.sig.message = "valid signature scheme";
    debug.sig.result = true;
    debug.sig.type = "XMSS";
    let height = parseInt(b[3], 2);
    height *= 2;
    debug.sig.height = height;
    debug.sig.number = Math.pow(2, height); // eslint-disable-line
    passed += 1;
  } else {
    debug.sig.message = "invalid signature scheme";
    debug.sig.result = false;
  }
  if (passed === 2) {
    debug.result = true;
  } else {
    debug.result = false;
  }
  return debug;
};

function hexString(q) {
  let passed = 0;
  const debug = {
    len: {},
    startQ: {},
    signature: {},
    checksum: {},
    hash: {},
    sig: {}
  };

  if (checklength(q)) {
    debug.len.message = "length ok";
    debug.len.result = true;
    passed += 1;
  } else {
    debug.len.message = "length bad";
    debug.len.result = false;
  }

  if (checkQ(q)) {
    debug.startQ.message = "starts with Q ok";
    debug.startQ.result = true;
    passed += 1;
  } else {
    debug.startQ.message = "does not start with Q";
    debug.startQ.result = false;
  }

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
    debug.checksum.message = "checksum ok";
    debug.checksum.result = true;
    passed += 1;
  } else {
    debug.checksum.message = "bad address checksum";
    debug.checksum.result = false;
  }
  if (passed === 4) {
    debug.result = true;
  } else {
    debug.result = false;
  }
  return debug;
};

module.exports = {
  /**
   * Reports the current module version
   * @return {string} version
   */
   version: function() {
     return '2.0.0'
   },
   hexString: function (q) {
     if (q === undefined) {
       return {result: false, error: 'Missing parameter'}
     }
     return hexString(q)
   },
 };
},{"sha256":3}]},{},[4])(4)
});
