'use strict';

var expect = require('chai').expect;
var validate = require('../index.js');

describe('#validateHexString', function() {
    it('should return true: argument is a valid address', function() {
        var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
        expect(result).to.have.property('result',true);
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
        expect(result).to.have.property('result',false);
    });
    it('should return false: argument does NOT have an initial Q', function() {
        var result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
        expect(result.startQ).to.have.property('result',false);
    });
    it('should return true: argument is a valid address length', function() {
        var result = validate.hexString('A01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
        expect(result.len).to.have.property('result',true);
    });
    it('should return false: argument is NOT a valid address length', function() {
        var result = validate.hexString('A01070050d31c7f12399cd62e8271a6bd');
        expect(result.len).to.have.property('result',false);
    });
    it('should return true: argument does have a valid hashing mechanism', function() {
        var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
        expect(result.hash).to.have.property('result',true);
    });
    it('should return false: argument does NOT a valid hashing mechanism', function() {
        var result = validate.hexString('Q02070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
        expect(result.hash).to.have.property('result',false);
    });
    it('should return false: argument does NOT a valid checksum', function() {
        var result = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06185df55dc2f6afe3c2cd62e8271a6bd');
        expect(result.checksum).to.have.property('result',false);
    });
});