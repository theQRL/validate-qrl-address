var validateQrlAddress = (() => {
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };

  // node_modules/convert-hex/convert-hex.js
  var require_convert_hex = __commonJS({
    "node_modules/convert-hex/convert-hex.js"(exports, module) {
      !(function(globals) {
        "use strict";
        var convertHex = {
          bytesToHex: function(bytes) {
            return arrBytesToHex(bytes);
          },
          hexToBytes: function(hex) {
            if (hex.length % 2 === 1) throw new Error("hexToBytes can't have a string with an odd number of characters.");
            if (hex.indexOf("0x") === 0) hex = hex.slice(2);
            return hex.match(/../g).map(function(x) {
              return parseInt(x, 16);
            });
          }
        };
        function arrBytesToHex(bytes) {
          return bytes.map(function(x) {
            return padLeft(x.toString(16), 2);
          }).join("");
        }
        function padLeft(orig, len) {
          if (orig.length > len) return orig;
          return Array(len - orig.length + 1).join("0") + orig;
        }
        if (typeof module !== "undefined" && module.exports) {
          module.exports = convertHex;
        } else {
          globals.convertHex = convertHex;
        }
      })(exports);
    }
  });

  // node_modules/convert-string/convert-string.js
  var require_convert_string = __commonJS({
    "node_modules/convert-string/convert-string.js"(exports, module) {
      !(function(globals) {
        "use strict";
        var convertString = {
          bytesToString: function(bytes) {
            return bytes.map(function(x) {
              return String.fromCharCode(x);
            }).join("");
          },
          stringToBytes: function(str) {
            return str.split("").map(function(x) {
              return x.charCodeAt(0);
            });
          }
        };
        convertString.UTF8 = {
          bytesToString: function(bytes) {
            return decodeURIComponent(escape(convertString.bytesToString(bytes)));
          },
          stringToBytes: function(str) {
            return convertString.stringToBytes(unescape(encodeURIComponent(str)));
          }
        };
        if (typeof module !== "undefined" && module.exports) {
          module.exports = convertString;
        } else {
          globals.convertString = convertString;
        }
      })(exports);
    }
  });

  // node_modules/sha256/lib/sha256.js
  var require_sha256 = __commonJS({
    "node_modules/sha256/lib/sha256.js"(exports, module) {
      !(function(globals) {
        "use strict";
        var _imports = {};
        if (typeof module !== "undefined" && module.exports) {
          _imports.bytesToHex = require_convert_hex().bytesToHex;
          _imports.convertString = require_convert_string();
          module.exports = sha256;
        } else {
          _imports.bytesToHex = globals.convertHex.bytesToHex;
          _imports.convertString = globals.convertString;
          globals.sha256 = sha256;
        }
        var K = [];
        !(function() {
          function isPrime(n2) {
            var sqrtN = Math.sqrt(n2);
            for (var factor = 2; factor <= sqrtN; factor++) {
              if (!(n2 % factor)) return false;
            }
            return true;
          }
          function getFractionalBits(n2) {
            return (n2 - (n2 | 0)) * 4294967296 | 0;
          }
          var n = 2;
          var nPrime = 0;
          while (nPrime < 64) {
            if (isPrime(n)) {
              K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
              nPrime++;
            }
            n++;
          }
        })();
        var bytesToWords = function(bytes) {
          var words = [];
          for (var i = 0, b = 0; i < bytes.length; i++, b += 8) {
            words[b >>> 5] |= bytes[i] << 24 - b % 32;
          }
          return words;
        };
        var wordsToBytes = function(words) {
          var bytes = [];
          for (var b = 0; b < words.length * 32; b += 8) {
            bytes.push(words[b >>> 5] >>> 24 - b % 32 & 255);
          }
          return bytes;
        };
        var W = [];
        var processBlock = function(H, M, offset) {
          var a = H[0], b = H[1], c = H[2], d = H[3];
          var e = H[4], f = H[5], g = H[6], h = H[7];
          for (var i = 0; i < 64; i++) {
            if (i < 16) {
              W[i] = M[offset + i] | 0;
            } else {
              var gamma0x = W[i - 15];
              var gamma0 = (gamma0x << 25 | gamma0x >>> 7) ^ (gamma0x << 14 | gamma0x >>> 18) ^ gamma0x >>> 3;
              var gamma1x = W[i - 2];
              var gamma1 = (gamma1x << 15 | gamma1x >>> 17) ^ (gamma1x << 13 | gamma1x >>> 19) ^ gamma1x >>> 10;
              W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
            }
            var ch = e & f ^ ~e & g;
            var maj = a & b ^ a & c ^ b & c;
            var sigma0 = (a << 30 | a >>> 2) ^ (a << 19 | a >>> 13) ^ (a << 10 | a >>> 22);
            var sigma1 = (e << 26 | e >>> 6) ^ (e << 21 | e >>> 11) ^ (e << 7 | e >>> 25);
            var t1 = h + sigma1 + ch + K[i] + W[i];
            var t2 = sigma0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1 | 0;
            d = c;
            c = b;
            b = a;
            a = t1 + t2 | 0;
          }
          H[0] = H[0] + a | 0;
          H[1] = H[1] + b | 0;
          H[2] = H[2] + c | 0;
          H[3] = H[3] + d | 0;
          H[4] = H[4] + e | 0;
          H[5] = H[5] + f | 0;
          H[6] = H[6] + g | 0;
          H[7] = H[7] + h | 0;
        };
        function sha256(message, options) {
          ;
          if (message.constructor === String) {
            message = _imports.convertString.UTF8.stringToBytes(message);
          }
          var H = [
            1779033703,
            3144134277,
            1013904242,
            2773480762,
            1359893119,
            2600822924,
            528734635,
            1541459225
          ];
          var m = bytesToWords(message);
          var l = message.length * 8;
          m[l >> 5] |= 128 << 24 - l % 32;
          m[(l + 64 >> 9 << 4) + 15] = l;
          for (var i = 0; i < m.length; i += 16) {
            processBlock(H, m, i);
          }
          var digestbytes = wordsToBytes(H);
          return options && options.asBytes ? digestbytes : options && options.asString ? _imports.convertString.bytesToString(digestbytes) : _imports.bytesToHex(digestbytes);
        }
        sha256.x2 = function(message, options) {
          return sha256(sha256(message, { asBytes: true }), options);
        };
      })(exports);
    }
  });

  // src/index.js
  var require_index = __commonJS({
    "src/index.js"(exports, module) {
      var sha256 = require_sha256();
      var checklength = (q) => {
        if (q.length === 79) {
          return true;
        }
        return false;
      };
      var checkQ = (q) => {
        if (q.slice(0, 1) === "Q") {
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
        let tmp = "";
        let i = 128;
        for (i = 128; i >= 1; i /= 2) tmp += a & i ? "1" : "0";
        return tmp;
      }
      function split2Bits(a, n) {
        let buff = "";
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
        return qj[0] === qa[0] && qj[1] === qa[1] && qj[2] === qa[2] && qj[3] === qa[3];
      }
      function isMultisig(b) {
        let result = false;
        if (b[0].toString() === "0001" && b[1].toString() === "0001" && b[2].toString() === "0000" && b[3].toString() === "0000" && b[4].toString() === "0000" && b[5].toString() === "0000") {
          result = true;
        }
        return result;
      }
      function checkXMSS(q) {
        const debug = { hash: {}, sig: {} };
        let passed = 0;
        const qr = q.slice(1, 7);
        const a = toByteArray(qr);
        const b = split2Bits(a, 4)[0];
        if (isMultisig(b)) {
          return {
            result: true,
            sig: {
              type: "MULTISIG",
              result: true,
              message: "valid signature scheme",
              height: 0,
              number: 0
            },
            hash: {
              message: "valid HASH mechanism",
              result: true,
              function: "SHA2-256"
            }
          };
        }
        if (b[1].toString() === "0000" || b[1].toString() === "0001" || b[1].toString() === "0010") {
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
          debug.sig.number = Math.pow(2, height);
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
      }
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
        if (debug.len.result === false) {
          debug.sig.message = "invalid signature scheme";
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
            debug.checksum.message = "checksum ok";
            debug.checksum.result = true;
            passed += 1;
          } else {
            debug.checksum.message = "bad address checksum";
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
          return "3.0.1";
        },
        hexString(q) {
          if (q === void 0) {
            return { result: false, error: "Missing parameter" };
          }
          return hexString(q);
        }
      };
    }
  });
  return require_index();
})();
if (typeof module === 'object' && module.exports) { module.exports = validateQrlAddress; }
