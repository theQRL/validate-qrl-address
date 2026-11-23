/* global describe, it */

const { createHash } = require('crypto');
const { expect } = require('chai');
const validate = require('../src');
const bundle = require('../dist/validateQrlAddress');

function createAddress(descriptor) {
  const payload = descriptor + '50d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e';
  const checksum = createHash('sha256').update(Buffer.from(payload, 'hex')).digest('hex').slice(-8);
  return 'Q' + payload + checksum;
}

const mainnetAddress = 'Q0c0d00e3acde5fa627b3c0f2d723108c265f16b9667a19d811b3c99ac329028ec8abf52fc5cca6';

describe('QRL address validation', function () {
  const validDescriptors = [
    ['000200', 'XMSS', 'SHA2-256', 4],
    ['010500', 'XMSS', 'SHAKE-128', 10],
    ['020700', 'XMSS', 'SHAKE-256', 14],
    ['010f00', 'XMSS', 'SHAKE-128', 30],
    ['110000', 'MULTISIG', 'SHA2-256', 0],
    ['110100', 'MULTISIG', 'SHA2-256', 0],
    ['110001', 'MULTISIG', 'SHA2-256', 0],
  ];

  validDescriptors.forEach(([descriptor, type, hashFunction, height]) => {
    it(`accepts ${descriptor} and reports ${type} metadata`, function () {
      const result = validate.hexString(createAddress(descriptor).toUpperCase());
      expect(result.result).to.equal(true);
      expect(result.hash.function).to.equal(hashFunction);
      expect(result.sig).to.include({ type, height, number: height === 0 ? 0 : 2 ** height });
    });
  });

  it('accepts the token holder address from mainnet block 1796388', function () {
    const result = validate.hexString(mainnetAddress);
    expect(result.result).to.equal(true);
    expect(result.checksum.result).to.equal(true);
    expect(result.hash.result).to.equal(false);
  });

  ['300700', '050700', '010701', '010000', '010100'].forEach((descriptor) => {
    it(`accepts checksummed descriptor ${descriptor} with a descriptor diagnostic`, function () {
      const result = validate.hexString(createAddress(descriptor));
      expect(result.result).to.equal(true);
      expect(result.signature.result).to.equal(false);
    });
  });

  ['011000', '004700', '111000'].forEach((descriptor) => {
    it(`rejects unsupported address format in ${descriptor} despite a valid checksum`, function () {
      const result = validate.hexString(createAddress(descriptor));
      expect(result.result).to.equal(false);
      expect(result.hash.result).to.equal(false);
      expect(result.checksum.result).to.equal(true);
    });
  });

  const address = createAddress('010700');
  [1, 7, 71].forEach((position) => {
    it(`rejects non-hex input at position ${position}`, function () {
      const result = validate.hexString(address.slice(0, position) + 'G' + address.slice(position + 1));
      expect(result.result).to.equal(false);
      expect(result.error).to.contain('Invalid hex');
    });
  });

  [
    [null, 'Missing parameter'],
    [undefined, 'Missing parameter'],
    [12345, 'string'],
    ['', 'Empty'],
  ].forEach(([input, error]) => {
    it(`reports an input error for ${JSON.stringify(input)}`, function () {
      const result = validate.hexString(input);
      expect(result.result).to.equal(false);
      expect(result.error).to.contain(error);
    });
  });

  it('retains the exported constants', function () {
    expect(validate.CONSTANTS).to.include({
      ADDRESS_PREFIX: 'Q',
      ADDRESS_LENGTH: 79,
      HASH_FUNCTION_SHA2_256: 0,
      HASH_FUNCTION_SHAKE_128: 1,
      HASH_FUNCTION_SHAKE_256: 2,
      SIGNATURE_XMSS: 0,
      SIGNATURE_MULTISIG: 1,
    });
  });

  it('returns the same results from the source and the bundle', function () {
    [mainnetAddress, address, createAddress('110001'), createAddress('011000'), 'Q'].forEach((input) => {
      expect(bundle.hexString(input)).to.deep.equal(validate.hexString(input));
    });
  });
});
