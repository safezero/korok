const arguguard = require('arguguard')
const random = require('random-amorph')
const aes = require('aes-128-cbc-amorph')
const InvalidEncapsulationVersionError = require('./errors/InvalidEncapsulationVersion')
const InvalidEncapsulationLengthError = require('./errors/InvalidEncapsulationLength')
const InvalidChecksumError = require('./errors/InvalidChecksum')
const keccak256 = require('keccak256-amorph')

function Korok(key) {
  arguguard('Korok', ['Amorph'], arguments)
  this.key = key
}

function getChecksum(key) {
  return keccak256(key).as('array', (array) => {
    return array.slice(0, 4)
  })
}

Korok.prototype.derive = function(key) {
  arguguard('korok.derive', ['Amorph'], arguments)
  const prehash = this.key.as('array', (array) => {
    return array.concat(key.to('array'))
  })
  return keccak256(prehash)
}

Korok.prototype.encapsulate = function(passphrase, iv) {
  arguguard('korok.encapsulate', ['Amorph', 'Amorph'], arguments)
  const encrypted = aes.encrypt(this.key, keccak256(passphrase), iv)
  const checksum = getChecksum(this.key)
  return encrypted.as('array', (array) => {
    return [0].concat(iv.to('array')).concat(array).concat(checksum.to('array'))
  })
}

Korok.generate = function generate() {
  arguguard('Korok.generate', [], arguments)
  return new Korok(random(32))
}

Korok.unencapsulate = function unencapsulate(encapsulation, passphrase) {
  arguguard('Korok.unencapsulate', ['Amorph', 'Amorph'], arguments)
  const encapsulationArray = encapsulation.to('array')
  if (encapsulationArray.length !== 53) {
    throw new InvalidEncapsulationLengthError(`Encapsulation should be 49 bytes long, received ${encapsulationArray.length}`)
  }
  if (encapsulationArray[0] !== 0) {
    throw new InvalidEncapsulationVersionError(encapsulationArray[0])
  }
  const iv = encapsulation.as('array', (array) => {
    return array.slice(1, 17)
  })
  const ciphertext = encapsulation.as('array', (array) => {
    return array.slice(17, 49)
  })
  const key = aes.decrypt(ciphertext, keccak256(passphrase), iv)
  const checksum = encapsulation.as('array', (array) => {
    return array.slice(49)
  })
  if (!checksum.equals(getChecksum(key), 'buffer')) {
    throw new InvalidChecksumError()
  }
  return new Korok(key)
}

module.exports = Korok
