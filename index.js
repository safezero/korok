const aesjs = require('aes-js')
const InvalidChecksumError = require('./InvalidChecksumError')
const arrayEquals = require('array-equal')
const defunction = require('defunction')
const crypto = require('crypto')

const SplitTemplate = require('hendricks/lib/Split')
const DictionaryTemplate = require('hendricks/lib/Dictionary')
const FixedTemplate = require('hendricks/lib/Fixed')

const korokTemplate = new SplitTemplate('korok', 1, ['v0'], [
  new DictionaryTemplate('korok.v0', [
    new FixedTemplate('ivSalt', 16),
    new FixedTemplate('secretCiphertext', 32),
    new FixedTemplate('checksum', 4),
    new FixedTemplate('securityParamater', 1)
  ])
])

// TODO: # defunction
const Korok = module.exports = defunction(['Uint8Array', 'Uint8Array', 'Uint8Array', 'number'], '*', function Korok(ivSalt, secretCiphertext, checksum, securityParamater) {
  this.ivSalt = ivSalt
  this.secretCiphertext = secretCiphertext
  this.checksum = checksum
  this.securityParamater = securityParamater
})

Korok.prototype.getEncoding = defunction([], 'Uint8Array', function getEncoding() {
  return korokTemplate.encode({
    branch: 'v0',
    value: {
      ivSalt: this.ivSalt,
      secretCiphertext: this.secretCiphertext,
      checksum: this.checksum,
      securityParamater: new Uint8Array([this.securityParamater])
    }
  })
})

Korok.prototype.getKey = defunction(['Uint8Array'], '=>Uint8Array', function getKey(password) {
  return Korok.getKey(password, this.ivSalt, this.securityParamater)
})

Korok.prototype.getSecret = defunction(['Uint8Array'], '=>Uint8Array', function getSecret(password) {
  if (this.secret) {
    return Promise.resolve(this.secret)
  }
  return this.getKey(password).then((key) => {
    const aesCbc = new aesjs.ModeOfOperation.cbc(key, this.ivSalt)
    const secret = aesCbc.decrypt(this.secretCiphertext)
    this.secret = secret
    const checksum = Korok.getChecksum(secret)
    if (!arrayEquals(this.checksum, checksum)) {
      throw new InvalidChecksumError('Invalid Checksum')
    }
    return secret
  })
})

Korok.getKey = defunction(['Uint8Array', 'Uint8Array', 'number'], '=>Uint8Array', function getKey(password, salt, securityParamater) {
  return new Promise((resolve, reject) => {
    const iterations = Math.pow(2, securityParamater)
    crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (error, keyBuffer) => {
      if (error) {
        reject(error)
      } else {
        resolve(new Uint8Array(keyBuffer))
      }
    })
  })
})

Korok.generate = defunction(['Uint8Array', 'number'], '=>Korok', function generate(password, securityParamater) {
  const secret = new Uint8Array(crypto.randomBytes(32))
  return Korok.fromSecret(secret, password, securityParamater)
})

Korok.fromSecret = defunction(['Uint8Array', 'Uint8Array', 'number'], '=>Korok', function fromSecret(secret, password, securityParamater) {
  const ivSalt = new Uint8Array(crypto.randomBytes(16))
  return Korok.getKey(password, ivSalt, securityParamater).then((key) => {
    const aesCbc = new aesjs.ModeOfOperation.cbc(key, ivSalt)
    const secretCiphertext = aesCbc.encrypt(secret, key)
    const checksum = Korok.getChecksum(secret)
    const korok = new Korok(ivSalt, secretCiphertext, checksum, securityParamater)
    korok.secret = secret
    return korok
  })
})

Korok.getChecksum = defunction(['Uint8Array'], 'Uint8Array', function getChecksum(secret) {
  const secretBuffer = new Buffer(secret)
  const checksum32Buffer =  crypto.createHash('sha256').update(secretBuffer).digest()
  const checksum32 = new Uint8Array(checksum32Buffer)
  return checksum32.slice(-4)
})

Korok.fromEncoding = defunction(['Uint8Array'], 'Korok', function fromEncoding(encoding) {
  const pojo = korokTemplate.decode(encoding)
  return new Korok(pojo.value.ivSalt, pojo.value.secretCiphertext, pojo.value.checksum, pojo.value.securityParamater[0])
})

module.exports = Korok
