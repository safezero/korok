const Korok = require('./')
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
const InvalidChecksumError = require('./InvalidChecksumError')

chai.use(chaiAsPromised)
chai.should()

describe('Korok', () => {
  let korok
  let secret
  let encoding
  let korok1

  const password = new Uint8Array([0, 1, 2, 3, 4])

  it('should generate', () => {
    return Korok.generate(password, 20).then((_korok) => {
      korok = _korok
    })
  })
  
  it('should get secret', () => {
    return korok.getSecret(password).then((_secret) => {
      secret = _secret
      secret.should.be.instanceof(Uint8Array)
      secret.should.have.length(32)
    })
  })
  
  it('should get encoding', () => {
    encoding = korok.getEncoding()
    encoding.should.be.instanceof(Uint8Array)
    encoding.should.have.length(54)
  })
  
  it('should fromEncoding', () => {
    korok1 = Korok.fromEncoding(encoding) 
  })
  
  it('should get the same secret', () => {
    return korok1.getSecret(password).should.eventually.deep.equal(secret)
  })
  
  it('should throw invalid checksum error', () => {
    const badEncoding = encoding.slice()
    badEncoding[5] = (badEncoding[0]) + 1 % 256
    return Korok.fromEncoding(badEncoding).getSecret(password).should.eventually.be.rejectedWith(InvalidChecksumError)
  })
  
  it('should throw invalid checksum error (2)', () => {
    const badEncoding = encoding.slice()
    badEncoding[badEncoding.length - 1] = (badEncoding[badEncoding.length - 1]) + 1 % 256
    return Korok.fromEncoding(badEncoding).getSecret(password).should.eventually.be.rejectedWith(InvalidChecksumError)
  })
})
