'use strict';

var validate = require('./index.js');

console.log('is Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd a valid QRL address?');

var isValid = validate.hexString('Q01070050d31c7f123995f097bc98209e9231d663dc26e06085df55dc2f6afe3c2cd62e8271a6bd');
       
console.log(isValid.result);