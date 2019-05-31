'use strict';

var expect = require('chai').expect;
var validate = require('../index.js');

describe('#validateHexString', function() {
  it('should return true: argument is a valid address', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result).to.have.property('result', true);
  });
  it('should return xmss as name of signature scheme', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.type).to.equal('XMSS');
  });
  it('should return XMSS tree height of 14', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.height).to.equal(14);
  });
  it('should return number of XMSS signatures as 16384 (2^14)', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.number).to.equal(16384);
  });
  it('should return shake-128 as name of the hashing method', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash.function).to.equal('SHAKE-128');
  });
  it('should return false: argument is NOT a valid address', function() {
    var result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result).to.have.property('result', false);
  });
  it('should return true: argument does have an initial Q', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.startQ).to.have.property('result', true);
  });
  it('should return false: argument does NOT have an initial Q', function() {
    var result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.startQ).to.have.property('result', false);
  });
  it('should return true: argument is a valid address length', function() {
    var result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.len).to.have.property('result', true);
  });
  it('should return false: argument is NOT a valid address length', function() {
    var result = validate.hexString('A01070050d31c7f12399cd62e8271a6bd');
    expect(result.len).to.have.property('result', false);
  });
  it('should return true: argument does have a valid hashing mechanism', function() {
    var result = validate.hexString('Q02070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash).to.have.property('result', true);
  });
  it('should return false: argument does NOT a valid hashing mechanism', function() {
    var result = validate.hexString('Q03070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash).to.have.property('result', false);
  });
  it('should return false: argument does NOT a valid checksum', function() {
    var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06185df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.checksum).to.have.property('result', false);
  });
  it('should return sha2-256 as name of the hashing method', function() {
    var result = validate.hexString('Q00070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.hash.function).to.equal('SHA2-256');
  });
  it('should return shake-256 as name of the hashing method', function() {
    var result = validate.hexString('Q02260060d974fd1faf2c2b0c91d9e33cae9f1b42208c62169f946373ae64198b97b6479f6c8ce5');
    expect(result.hash.function).to.equal('SHAKE-256');
  });
  it('should return false: argument does not have a valid signature scheme', function() {
    var result = validate.hexString('Q13070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result.sig.result).to.equal(false);
  });
});


describe('#validateBech32', function() {
  it('should return true: argument is a valid address', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result).to.have.property('result', true);
  });
  it('should return xmss as name of signature scheme', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result.sig.type).to.equal('XMSS');
  });
  it('should return XMSS tree height of 14', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result.sig.height).to.equal(14);
  });
  it('should return number of XMSS signatures as 16384 (2^14)', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result.sig.number).to.equal(16384);
  });
  it('should return shake-128 as name of the hashing method', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result.hash.function).to.equal('SHAKE-128');
  });
  it('should return false: argument is NOT a valid address', function() {
    var result = validate.bech32('a1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result).to.have.property('result', false);
  });
  it('should return false: argument is NOT a valid address length', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6fr');
    expect(result).to.have.property('result', false);
  });
  it('should return true: argument does have a valid hashing mechanism', function() {
    var result = validate.bech32('q1qgrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43wjv3gwn');
    expect(result.hash).to.have.property('result', true);
  });
  it('should return false: argument does NOT a valid hashing mechanism', function() {
    var result = validate.bech32('q1qvrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43wk9vvyf');
    expect(result.hash).to.have.property('result', false);
  });
  it('should return false: argument does NOT have a valid BECH32 checksum', function() {
    var result = validate.bech32('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm23c7ze43w7hlys5');
    expect(result).to.have.property('result', false);
  });
  it('should return sha2-256 as name of the hashing method', function() {
    var result = validate.bech32('q1qqrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w67zq6w');
    expect(result.hash.function).to.equal('SHA2-256');
  });
  it('should return shake-256 as name of the hashing method', function() {
    var result = validate.bech32('q1qgnqqcxewn73ltev9vxfrk0r8jhf7x6zyzxxy95lj33h8tnyrx9e0dj83nrpga');
    expect(result.hash.function).to.equal('SHAKE-256');
  });
  it('should return false: argument does not have a valid signature scheme', function() {
    var result = validate.bech32('q1zvrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w46026y');
    expect(result.sig.result).to.equal(false);
  });
});


describe('#justValidateBothFormats', function() {
  it('should return true: this bech32 address is a valid address', function() {
    var result = validate.validate('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2actm2lc7ze43w7hlys5');
    expect(result).to.have.property('result', true);
  });
  it('should return true: this hexstring address is a valid address', function() {
    var result = validate.validate('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
    expect(result).to.have.property('result', true);
  });
  it('should return true: this bech32 address is an invalid address', function() {
    var result = validate.validate('q1qyrsq5xnr3l3ywv47ztmexpqn6frr4nrmsnwqcy9ma2acc7ze43w7hlys5');
    expect(result).to.have.property('result', false);
  });
  it('should return true: this hexstring address is an invalid address', function() {
    var result = validate.validate('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2fe3c2cd62e8271a6bd');
    expect(result).to.have.property('result', false);
  });
});