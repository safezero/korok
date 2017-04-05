const Korok = require('./')
const random = require('random-amorph')
const _ = require('lodash')
const chai = require('chai')

const InvalidChecksumError = require('./errors/InvalidChecksum')
const InvalidEncapsulationLengthError = require('./errors/InvalidEncapsulationLength')
const InvalidEncapsulationVersionError = require('./errors/InvalidEncapsulationVersion')

const Amorph = require('amorph')
Amorph.loadPlugin(require('amorph-bignumber'))
Amorph.ready()

chai.should()

describe('Korok', () => {
  let korok
  let korok2
  const derivationKeys = _.range(10).map(() => {
    return random(random(1).to('number'))
  })
  let korokEncapsulation
  let korok2Encapsulation
  const passphrase = new Amorph('my passphrase', 'ascii')

  it('should generate', () => {
    korok = Korok.generate()
  })
  it('should create from key', () => {
    korok2 = new Korok(korok.key)
  })
  it('korok and korok2 should derive the same keys', () => {
    derivationKeys.forEach((derivationKey) => {
      korokKey = korok.derive(derivationKey)
      korok2Key = korok2.derive(derivationKey)
      korokKey.equals(korok2Key, 'buffer').should.equal(true)
    })
  })
  it('should encapsulate korok and korok2', () => {
    korokEncapsulation = korok.encapsulate(passphrase, random(16))
    korok2Encapsulation = korok.encapsulate(passphrase, random(16))
  })
  it('should unencapsulate korok correctly', () => {
    Korok.unencapsulate(korokEncapsulation, passphrase).key.equals(korok.key).should.equal(true)
  })
  it('should unencapsulate korok2 correctly', () => {
    Korok.unencapsulate(korok2Encapsulation, passphrase).key.equals(korok.key).should.equal(true)
  })
  describe('errors', () => {
    it('should throw InvalidVersionError', () => {
      const corruptedEncapsulation = korokEncapsulation.as('array', (array) => {
        const clone = _.clone(array)
        clone[0] = random(1).to('number')
        return clone
      })
      ;(() => {
        Korok.unencapsulate(corruptedEncapsulation, passphrase)
      }).should.throw(InvalidEncapsulationVersionError)
    })
    it('should throw InvalidEncapsulationLengthError', () => {
      const bads = [random(0), random(58), random(60)].forEach((bad) => {
        ;(() => {
          Korok.unencapsulate(bad, passphrase)
        }).should.throw(InvalidEncapsulationLengthError)
      })
    })
    it('should throw InvalidChecksumError', () => {
      korokEncapsulation.to('array').forEach((byte, index) => {
        if (index === 0) {
          return
        }
        const corruptedEncapsulation = korokEncapsulation.as('array', (array) => {
          const clone = _.clone(array)
          clone[index] = random(1).to('number')
          return clone
        })
        ;(() => {
          Korok.unencapsulate(corruptedEncapsulation, passphrase)
        }).should.throw(InvalidChecksumError)
      })
    })
  })
})
