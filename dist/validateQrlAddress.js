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
      var ADDRESS_PREFIX = "Q";
      var DESCRIPTOR_LENGTH_BYTES = 3;
      var PUBLIC_KEY_LENGTH_BYTES = 32;
      var CHECKSUM_LENGTH_BYTES = 4;
      var PAYLOAD_LENGTH_BYTES = DESCRIPTOR_LENGTH_BYTES + PUBLIC_KEY_LENGTH_BYTES;
      var TOTAL_INTERNAL_LENGTH = PAYLOAD_LENGTH_BYTES + CHECKSUM_LENGTH_BYTES;
      var ADDRESS_LENGTH = 1 + TOTAL_INTERNAL_LENGTH * 2;
      var CHECKSUM_START = 1 + PAYLOAD_LENGTH_BYTES * 2;
      var HASH_FUNCTION_SHA2_256 = 0;
      var HASH_FUNCTION_SHAKE_128 = 1;
      var HASH_FUNCTION_SHAKE_256 = 2;
      var SIGNATURE_XMSS = 0;
      var SIGNATURE_MULTISIG = 1;
      var ADDRESS_FORMAT_SHA256_2X = 0;
      var MULTISIG_MARKER = 17;
      var HASH_FUNCTIONS = [
        "SHA2-256",
        "SHAKE-128",
        "SHAKE-256"
      ];
      function hexToBytes(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
          const pair = hex.slice(i, i + 2);
          if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
            throw new Error(`Invalid hex pair '${pair}' at position ${i}`);
          }
          bytes.push(parseInt(pair, 16));
        }
        return bytes;
      }
      function describeSignature(bytes, addressFormat) {
        const scheme = bytes[0] >> 4;
        const hashFunction = HASH_FUNCTIONS[bytes[0] & 15];
        const validFormat = addressFormat === ADDRESS_FORMAT_SHA256_2X;
        const isMultisig = bytes[0] === MULTISIG_MARKER;
        const hash = {
          result: validFormat && hashFunction !== void 0,
          function: validFormat ? isMultisig ? "SHA2-256" : hashFunction : void 0
        };
        if (!validFormat) {
          hash.message = `invalid address format: ${addressFormat} (must be 0 for SHA256_2X)`;
        } else {
          hash.message = hash.result ? "valid HASH mechanism" : `invalid HASH mechanism: ${bytes[0] & 15}`;
        }
        const sig = { result: false, message: "", height: void 0, number: void 0, type: void 0 };
        if (isMultisig) {
          Object.assign(sig, {
            result: true,
            message: "valid signature scheme",
            type: "MULTISIG",
            height: 0,
            number: 0
          });
        } else if (bytes[2] !== 0) {
          sig.message = "invalid signature scheme: reserved byte must be 0";
        } else if (scheme !== SIGNATURE_XMSS) {
          sig.message = `invalid signature scheme: ${scheme}`;
        } else {
          sig.type = "XMSS";
          const height = (bytes[1] & 15) * 2;
          if (height < 4) {
            sig.message = `invalid XMSS height: ${height} (must be even, 4-30)`;
          } else {
            sig.result = true;
            sig.message = "valid signature scheme";
            sig.height = height;
            sig.number = 2 ** height;
          }
        }
        return { hash, sig };
      }
      function hexString(q) {
        const validPrefix = q.startsWith(ADDRESS_PREFIX);
        const validLength = q.length === ADDRESS_LENGTH;
        const debug = {
          len: {
            message: validLength ? `length ok (${ADDRESS_LENGTH} characters)` : `length bad (${q.length} characters, expected ${ADDRESS_LENGTH})`,
            result: validLength
          },
          startQ: {
            message: validPrefix ? `starts with ${ADDRESS_PREFIX} ok` : `does not start with ${ADDRESS_PREFIX}`,
            result: validPrefix
          },
          signature: {},
          checksum: {},
          hash: {},
          sig: { message: "invalid signature scheme", result: false },
          result: false
        };
        if (!validLength) return debug;
        const bytes = hexToBytes(q.slice(1));
        const addressFormat = bytes[1] >> 4;
        const { hash, sig } = describeSignature(bytes, addressFormat);
        debug.hash = hash;
        debug.sig = sig;
        debug.signature = { message: `${hash.message} / ${sig.message}`, result: hash.result && sig.result };
        const expectedChecksum = sha256(bytes.slice(0, PAYLOAD_LENGTH_BYTES)).slice(-CHECKSUM_LENGTH_BYTES * 2);
        const validChecksum = q.slice(CHECKSUM_START).toLowerCase() === expectedChecksum;
        debug.checksum = { message: validChecksum ? "checksum ok" : "bad address checksum", result: validChecksum };
        debug.result = validPrefix && addressFormat === ADDRESS_FORMAT_SHA256_2X && validChecksum;
        return debug;
      }
      module.exports = {
        /**
         * Reports the current module version
         * @return {string} version
         */
        version() {
          return "3.0.2";
        },
        /**
         * Validates a QRL address hex string
         * @param {string} q - Address to validate (79 hex characters starting with Q)
         * @returns {object} Validation result object with detailed info
         */
        hexString(q) {
          if (q === void 0 || q === null) {
            return { result: false, error: "Missing parameter" };
          }
          if (typeof q !== "string") {
            return { result: false, error: "Parameter must be a string" };
          }
          if (q.length === 0) {
            return { result: false, error: "Empty address" };
          }
          try {
            return hexString(q);
          } catch (error) {
            return { result: false, error: error.message };
          }
        },
        // Constants exported for external use
        CONSTANTS: {
          ADDRESS_PREFIX,
          ADDRESS_LENGTH,
          DESCRIPTOR_LENGTH_BYTES,
          PUBLIC_KEY_LENGTH_BYTES,
          CHECKSUM_LENGTH_BYTES,
          HF_START: 0,
          HF_END: 3,
          SIG_START: 4,
          SIG_END: 7,
          P1_START: 8,
          P1_END: 11,
          AF_START: 12,
          AF_END: 15,
          P3_START: 16,
          P3_END: 23,
          HASH_FUNCTION_SHA2_256,
          HASH_FUNCTION_SHAKE_128,
          HASH_FUNCTION_SHAKE_256,
          SIGNATURE_XMSS,
          SIGNATURE_MULTISIG,
          ADDRESS_FORMAT_SHA256_2X
        }
      };
    }
  });
  return require_index();
})();
if (typeof module === 'object' && module.exports) { module.exports = validateQrlAddress; }
