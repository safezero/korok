const arguguard = require('arguguard')
const random = require('random-amorph')
const aes = require('aes-128-cbc-amorph')
const InvalidEncapsulationVersionError = require('./errors/InvalidEncapsulationVersion')
const InvalidEncapsulationLengthError = require('./errors/InvalidEncapsulationLength')
const InvalidChecksumError = require('./errors/InvalidChecksum')
const keccak256 = require('keccak256-amorph')
const arrayEquals = require('array-equal')

function Korok(key) {
  arguguard('Korok', ['Amorph'], arguments)
  this.key = key
}

function getChecksum(key) {
  return keccak256(key).as('uint8Array', (uint8Array) => {
    return uint8Array.slice(0, 4)
  })
}

Korok.prototype.derive = function(key) {
  arguguard('korok.derive', ['Amorph'], arguments)
  const prehash = this.key.as('uint8Array', (_keyUint8Array) => {
    const keyUint8Array = key.to('uint8Array')
    const prehashUint8Array = new Uint8Array(_keyUint8Array.length + keyUint8Array.length)
    prehashUint8Array.set(_keyUint8Array)
    prehashUint8Array.set(keyUint8Array, _keyUint8Array.length)
    return prehashUint8Array
  })
  return keccak256(prehash)
}

Korok.prototype.encapsulate = function(passphrase, iv) {
  arguguard('korok.encapsulate', ['Amorph', 'Amorph'], arguments)
  const encrypted = aes.encrypt(this.key, keccak256(passphrase), iv)
  const checksum = getChecksum(this.key)
  return encrypted.as('uint8Array', (encryptedUint8Array) => {
    const ivUint8Array = iv.to('uint8Array')
    const checksumUint8Array = checksum.to('uint8Array')
    const encapsulationUint8Array = new Uint8Array(1 + ivUint8Array.length + encryptedUint8Array.length + checksumUint8Array.length)
    encapsulationUint8Array.set(ivUint8Array, 1)
    encapsulationUint8Array.set(encryptedUint8Array, 1 + ivUint8Array.length)
    encapsulationUint8Array.set(checksumUint8Array, 1 + ivUint8Array.length + encryptedUint8Array.length)
    return encapsulationUint8Array
  })
}

Korok.generate = function generate() {
  arguguard('Korok.generate', [], arguments)
  return new Korok(random(32))
}

Korok.unencapsulate = function unencapsulate(encapsulation, passphrase) {
  arguguard('Korok.unencapsulate', ['Amorph', 'Amorph'], arguments)
  const Amorph = encapsulation.constructor
  const encapsulationUint8Array = encapsulation.to('uint8Array')
  if (encapsulationUint8Array.length !== 53) {
    throw new InvalidEncapsulationLengthError(`Encapsulation should be 53 bytes long, received ${encapsulationUint8Array.length}`)
  }
  if (encapsulationUint8Array[0] !== 0) {
    throw new InvalidEncapsulationVersionError(encapsulationUint8Array[0])
  }
  const ivUint8Array = encapsulationUint8Array.slice(1, 17)
  const ciphertextUint8Array = encapsulationUint8Array.slice(17, 49)
  const key = aes.decrypt(
    new Amorph(ciphertextUint8Array, 'uint8Array'),
    keccak256(passphrase),
    new Amorph(ivUint8Array, 'uint8Array')
  )
  const checksumUint8Array = encapsulationUint8Array.slice(49)

  if (!arrayEquals(checksumUint8Array, getChecksum(key).to('uint8Array'))) {
    throw new InvalidChecksumError('Checksum does not match')
  }
  return new Korok(key)
}

module.exports = Korok
