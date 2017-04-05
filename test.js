const Korok = require('./')
const random = require('random-amorph')
const _ = require('lodash')
const chai = require('chai')

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
  let korokEncapsulated
  let korok2Encapsulated
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
    korokEncapsulated = korok.encapsulate(passphrase, random(16))
    korok2Encapsulated = korok.encapsulate(passphrase, random(16))
  })
  it('should unencapsulate korok correctly', () => {
    Korok.unencapsulate(korokEncapsulated, passphrase).key.equals(korok.key).should.equal(true)
  })
  it('should unencapsulate korok2 correctly', () => {
    Korok.unencapsulate(korok2Encapsulated, passphrase).key.equals(korok.key).should.equal(true)
  })
})
