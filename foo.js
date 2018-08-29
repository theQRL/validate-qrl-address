'use strict';

var validate = require('./index.js');


var address = 'Q0205003350a8e3a7642c25020d8ed38b7489c548c92cabb23aaa232b7476bfc28da93f821a7419'
var isValid = validate.hexString(address);
// var address = 'q1qypqplxc2tcc37m8plnx89cnvw475wqh45mu6k6faurj3alyfyfym3uxmplj2dg0r9hp7'
// var isValid = validate.bech32(address);

console.log('is', address, 'a valid QRL address?');

console.log(isValid.result);
console.log(isValid.sig.type);
console.log(isValid.sig.number);
console.log(isValid.hash.function);