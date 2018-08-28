'use strict';

var validate = require('./index.js');

var address = 'Q0205003350a8e3a7642c25020d8ed38b7489c548c92cabb23aaa232b7476bfc28da93f821a7419'
console.log('is', address, ' a valid QRL address?');
// console.log('is q1qypqplxc2tcc37m8plnx89cnvw475wqh45mu6k6faurj3alyfyfym3uxmplj2dg0r9hp7 a valid QRL address?');

var isValid = validate.hexString(address);
// var isValid = validate.bech32('q1qypqplxc2tcc37m8plnx89cnvw475wqh45mu6k6faurj3alyfyfym3uxmplj2dg0r9hp7')

console.log(isValid.result);
console.log(isValid.sig.type);
console.log(isValid.sig.number);
console.log(isValid.hash.function);