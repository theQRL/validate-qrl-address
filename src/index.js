/* eslint no-bitwise: 0 */
const sha256 = require('sha256');

const ADDRESS_PREFIX = 'Q';
const DESCRIPTOR_LENGTH_BYTES = 3;
// The address stores a hash of the extended public key.
const PUBLIC_KEY_LENGTH_BYTES = 32;
const CHECKSUM_LENGTH_BYTES = 4;
const PAYLOAD_LENGTH_BYTES = DESCRIPTOR_LENGTH_BYTES + PUBLIC_KEY_LENGTH_BYTES;
const TOTAL_INTERNAL_LENGTH = PAYLOAD_LENGTH_BYTES + CHECKSUM_LENGTH_BYTES;
const ADDRESS_LENGTH = 1 + TOTAL_INTERNAL_LENGTH * 2;
const CHECKSUM_START = 1 + PAYLOAD_LENGTH_BYTES * 2;

const HASH_FUNCTION_SHA2_256 = 0;
const HASH_FUNCTION_SHAKE_128 = 1;
const HASH_FUNCTION_SHAKE_256 = 2;
const SIGNATURE_XMSS = 0;
const SIGNATURE_MULTISIG = 1;
const ADDRESS_FORMAT_SHA256_2X = 0;
const MULTISIG_MARKER = 0x11;

const HASH_FUNCTIONS = [
  'SHA2-256',
  'SHAKE-128',
  'SHAKE-256',
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
  const hashFunction = HASH_FUNCTIONS[bytes[0] & 0x0f];
  const validFormat = addressFormat === ADDRESS_FORMAT_SHA256_2X;
  const isMultisig = bytes[0] === MULTISIG_MARKER;
  const hash = {
    result: validFormat && hashFunction !== undefined,
    function: validFormat ? (isMultisig ? 'SHA2-256' : hashFunction) : undefined,
  };

  if (!validFormat) {
    hash.message = `invalid address format: ${addressFormat} (must be 0 for SHA256_2X)`;
  } else {
    hash.message = hash.result ? 'valid HASH mechanism' : `invalid HASH mechanism: ${bytes[0] & 0x0f}`;
  }

  const sig = { result: false, message: '', height: undefined, number: undefined, type: undefined };
  if (isMultisig) {
    Object.assign(sig, {
      result: true, message: 'valid signature scheme', type: 'MULTISIG', height: 0, number: 0,
    });
  } else if (bytes[2] !== 0) {
    sig.message = 'invalid signature scheme: reserved byte must be 0';
  } else if (scheme !== SIGNATURE_XMSS) {
    sig.message = `invalid signature scheme: ${scheme}`;
  } else {
    sig.type = 'XMSS';
    const height = (bytes[1] & 0x0f) * 2;
    if (height < 4) {
      sig.message = `invalid XMSS height: ${height} (must be even, 4-30)`;
    } else {
      sig.result = true;
      sig.message = 'valid signature scheme';
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
      message: validLength
        ? `length ok (${ADDRESS_LENGTH} characters)`
        : `length bad (${q.length} characters, expected ${ADDRESS_LENGTH})`,
      result: validLength,
    },
    startQ: {
      message: validPrefix ? `starts with ${ADDRESS_PREFIX} ok` : `does not start with ${ADDRESS_PREFIX}`,
      result: validPrefix,
    },
    signature: {},
    checksum: {},
    hash: {},
    sig: { message: 'invalid signature scheme', result: false },
    result: false,
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
  debug.checksum = { message: validChecksum ? 'checksum ok' : 'bad address checksum', result: validChecksum };

  // QRL consensus checks length, address format and checksum. Descriptor
  // diagnostics can fail for addresses that already exist on chain.
  debug.result = validPrefix && addressFormat === ADDRESS_FORMAT_SHA256_2X && validChecksum;
  return debug;
}

module.exports = {
  /**
   * Reports the current module version
   * @return {string} version
   */
  version() {
    return '3.0.2';
  },

  /**
   * Validates a QRL address hex string
   * @param {string} q - Address to validate (79 hex characters starting with Q)
   * @returns {object} Validation result object with detailed info
   */
  hexString(q) {
    if (q === undefined || q === null) {
      return { result: false, error: 'Missing parameter' };
    }

    if (typeof q !== 'string') {
      return { result: false, error: 'Parameter must be a string' };
    }

    if (q.length === 0) {
      return { result: false, error: 'Empty address' };
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
    ADDRESS_FORMAT_SHA256_2X,
  },
};
