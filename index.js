const sha256 = require('sha256')
const b32 = require('bech32')

const checklength = (q) => {
  if (q.length === 79) {
    return true
  }
  return false
}

const checkQ = (q) => {
  if (q.slice(0, 1) === 'Q') {
    return true
  }
  return false
}

function hexToBytes(hex) {
  const bytes = []
  for (let c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16))
  }
  return bytes
}

function byte2bits(a) {
  let tmp = ''
  for (let i = 128; i >= 1; i /= 2) tmp += a & i ? '1' : '0'
  return tmp
}

function split2Bits(a, n) {
  let buff = ''
  const b = []
  for (let i = 0; i < a.length; i++) {
    buff += byte2bits(a[i])
    while (buff.length >= n) {
      b.push(buff.substr(0, n))
      buff = buff.substr(n)
    }
  }
  return [b, buff]
}

function toByteArray(hexStringInput) {
  const result = []
  while (hexStringInput.length >= 2) {
    result.push(parseInt(hexStringInput.substring(0, 2), 16))
    hexStringInput = hexStringInput.substring(2, hexStringInput.length)
  }
  return result
}

function checkDescriptor(bits) {
  const debug = { hash: {}, sig: {} }
  let passed = 0
  if (
    (bits[1].toString() === '0000')
    || (bits[1].toString() === '0001')
    || (bits[1].toString() === '0010')
  ) {
    debug.hash.message = 'valid HASH mechanism'
    debug.hash.result = true
    passed += 1
    if (bits[1].toString() === '0000') { debug.hash.function = 'SHA2-256' }
    if (bits[1].toString() === '0001') { debug.hash.function = 'SHAKE-128' }
    if (bits[1].toString() === '0010') { debug.hash.function = 'SHAKE-256' }
  } else {
    debug.hash.message = 'invalid HASH mechanism'
    debug.hash.result = false
  }
  if (bits[0].toString() === '0000') {
    debug.sig.message = 'valid signature scheme'
    debug.sig.result = true
    debug.sig.type = 'XMSS'
    let height = parseInt(bits[3], 2)
    height *= 2
    debug.sig.height = height
    debug.sig.number = Math.pow(2, height) // eslint-disable-line
    passed += 1
  } else {
    debug.sig.message = 'invalid signature scheme'
    debug.sig.result = false
  }
  if (passed === 2) {
    debug.result = true
  } else {
    debug.result = false
  }
  return debug
}
const checkHash = (q) => {
  const qs = q.slice(1, 71)
  const qa = hexToBytes(q.slice(71, 80))
  const qx = sha256(hexToBytes(qs))
  const qm = qx.slice(56, 64)
  const qj = hexToBytes(qm)
  return (
    qj[0] === qa[0] && qj[1] === qa[1] && qj[2] === qa[2] && qj[3] === qa[3]
  )
}

const prepareDescriptorFromHex = (q) => {
  const qr = q.slice(1, 7)
  const a = toByteArray(qr)
  const descriptor = (split2Bits(a, 4))[0]
  return descriptor
}


function b32Encode(input) {
  return b32.encode('q', b32.toWords(input))
}

function b32Decode(input) {
  const a = b32.decode(input)
  if (a.prefix !== 'q') {
    throw new Error('This is not a QRL address')
  }
  return Uint8Array.from(b32.fromWords(a.words))
}

const bech32 = (q) => {
  const debug = {
    hash: {},
    sig: {},
    result: false,
  }

  let decoded = ''
  try {
    decoded = b32.decode(q)
    if (decoded.prefix !== 'q') {
      return debug
    }
    debug.result = true
  } catch (e) { // This happens when it fails the BECH32 checksum
    return debug
  }
  const bin = new Uint8Array(b32.fromWords(decoded.words))

  const descriptor = (split2Bits(bin, 4))[0]
  const d = checkDescriptor(descriptor)
  debug.hash = d.hash
  debug.sig = d.sig

  return debug
}

const hexString = (q) => {
  let passed = 0
  const debug = {
    len: {},
    startQ: {},
    signature: {},
    checksum: {},
    hash: {},
    sig: {},
  }

  if (checklength(q)) {
    debug.len.message = 'length ok'
    debug.len.result = true
    passed += 1
  } else {
    debug.len.message = 'length bad'
    debug.len.result = false
  }

  if (checkQ(q)) {
    debug.startQ.message = 'starts with Q ok'
    debug.startQ.result = true
    passed += 1
  } else {
    debug.startQ.message = 'does not start with Q'
    debug.startQ.result = false
  }

  const d = prepareDescriptorFromHex(q)
  const hashSig = checkDescriptor(d)
  debug.signature.message = `${hashSig.hash.message} / ${hashSig.sig.message}`
  debug.sig.message = hashSig.sig.message
  debug.sig.result = hashSig.sig.result
  debug.hash.result = hashSig.hash.result
  debug.hash.message = hashSig.hash.message
  debug.hash.function = hashSig.hash.function
  debug.sig.height = hashSig.sig.height
  debug.sig.number = hashSig.sig.number
  debug.sig.type = hashSig.sig.type
  if (hashSig.result) {
    debug.signature.result = true
    passed += 1
  } else {
    debug.signature.result = false
  }

  if (checkHash(q)) {
    debug.checksum.message = 'checksum ok'
    debug.checksum.result = true
    passed += 1
  } else {
    debug.checksum.message = 'bad address checksum'
    debug.checksum.result = false
  }
  if (passed === 4) {
    debug.result = true
  } else {
    debug.result = false
  }
  return debug
}

const validate = (address) => {
  // Takes any address, hex or Bech32, and validates it.
  if (address[0] === 'q') {
    return bech32(address)
  }
  return hexString(address)
}

exports.bech32 = bech32
exports.hexString = hexString
exports.validate = validate
// module.exports = prepareDescriptorFromHex
// module.exports = checkQ
// module.exports = checklength
