/* global it, describe */

const { expect } = require('chai');
const validate = require('../src/index.js');

describe('#version', function () {
  it('.version should report same version as in npm package.json file (=' + process.env.npm_package_version + ')', function () {
    const result = validate.version();
    expect(result).to.equal(process.env.npm_package_version);
  });
});

describe('#validateHexString', function () {
  it('should return true: argument is a valid address', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result).to.have.property('result', true);
  });
  it('should true for a valid multisig address', function () {
    const result = validate.hexString('Q1100005a1bd669e0d1a89f28e1af87b2f7035efd10c1f129fc062717db77b8bf3802ce9882386d');
    expect(result).to.have.property('result', true);
  });
  it('multisig hash function is sha2-256', function () {
    const result = validate.hexString('Q1100005a1bd669e0d1a89f28e1af87b2f7035efd10c1f129fc062717db77b8bf3802ce9882386d');
    expect(result.hash.function).to.equal('SHA2-256');
  });
  it('multisig has a treeheight of 0 (as it is not a tree)', function () {
    const result = validate.hexString('Q1100005a1bd669e0d1a89f28e1af87b2f7035efd10c1f129fc062717db77b8bf3802ce9882386d');
    expect(result.sig.height).to.equal(0);
  });
  it('multisig has 0 signatures as these come from participants', function () {
    const result = validate.hexString('Q1100005a1bd669e0d1a89f28e1af87b2f7035efd10c1f129fc062717db77b8bf3802ce9882386d');
    expect(result.sig.number).to.equal(0);
  });
  it('should return multisig as name of signature scheme for a multisig address', function () {
    const result = validate.hexString('Q1100005a1bd669e0d1a89f28e1af87b2f7035efd10c1f129fc062717db77b8bf3802ce9882386d');
    expect(result.sig.type).to.equal('MULTISIG');
  });
  it('should return xmss as name of signature scheme for an xmss address', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.type).to.equal('XMSS');
  });
  it('should return XMSS tree height of 14', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.height).to.equal(14);
  });
  it('should return number of XMSS signatures as 16384 (2^14)', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.number).to.equal(16384);
  });
  it('should return shake-128 as name of the hashing method', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash.function).to.equal('SHAKE-128');
  });
  it('should return false: argument is NOT a valid address', function () {
    const result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result).to.have.property('result', false);
  });
  it('should return true: argument does have an initial Q', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.startQ).to.have.property('result', true);
  });
  it('should return false: argument does NOT have an initial Q', function () {
    const result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.startQ).to.have.property('result', false);
  });
  it('should return true: argument is a valid address length', function () {
    const result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.len).to.have.property('result', true);
  });
  it('should return false: argument is NOT a valid address length', function () {
    const result = validate.hexString('A01070050d31c7f12399cd62e8271a6bd');
    expect(result.len).to.have.property('result', false);
  });
  it('should return true: argument does have a valid hashing mechanism', function () {
    const result = validate.hexString('Q02070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash).to.have.property('result', true);
  });
  it('should return false: argument does NOT a valid hashing mechanism', function () {
    const result = validate.hexString('Q03070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash).to.have.property('result', false);
  });
  it('should return false: argument does NOT a valid checksum', function () {
    const result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06185df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.checksum).to.have.property('result', false);
  });
  it('should return sha2-256 as name of the hashing method', function () {
    const result = validate.hexString('Q00070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash.function).to.equal('SHA2-256');
  });
  it('should return shake-256 as name of the hashing method', function () {
    const result = validate.hexString('Q02260060d974fd1faf2c2b0c91d9e33cae9f1b42208c62169f946373ae64198b97b6479f6c8ce5');
    expect(result.hash.function).to.equal('SHAKE-256');
  });
  it('should return false: argument does not have a valid signature scheme', function () {
    const result = validate.hexString('Q13070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.result).to.equal(false);
  });
  it('should return false where no argument is passed', function () {
    const result = validate.hexString();
    expect(result.result).to.equal(false);
  });
  it('should always return false where zero length hexstring is passed', function () {
    const result = validate.hexString('');
    expect(result.result).to.equal(false);
  });
  it('should always return false where single digit hexstring is passed', function () {
    const result = validate.hexString('Q');
    expect(result.result).to.equal(false);
  });
  it('should always return false where two digit hexstring is passed', function () {
    const result = validate.hexString('Q1');
    expect(result.result).to.equal(false);
  });
});
