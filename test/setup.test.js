const { expect } = require('chai');
const {
  withOptionsPaInstanceCreator,
  emptyPaInstanceCreator,
  paOptions,
} = require('./testHelper');

describe('#new PlugableAuthentication()', () => {
  context('empty or incomplete option', function () {
    it("should throw error 'Mongo URI is required'", function () {
      expect(emptyPaInstanceCreator).to.throw('Mongo URI is required');
    });

    it("should throw error 'Mongo Collection name is required'", function () {
      expect(withOptionsPaInstanceCreator({ uri: paOptions.uri })).to.throw(
        'Mongo Collection name is required'
      );
    });

    it("should throw error 'JWT secret is required'", function () {
      expect(
        withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
        })
      ).to.throw('JWT secret is required');
    });

    it("should throw error 'Encryption secret is required'", function () {
      expect(
        withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
        })
      ).to.throw('Encryption secret is required');
    });
    it("should throw error 'Cookie ID is required'", function () {
      expect(
        withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
          encryptSecret: paOptions.encryptSecret,
        })
      ).to.throw('Cookie ID is required');
    });
  });
  context('with minimum required options', function () {
    it('should not throw any error', function () {
      expect(
        withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
          encryptSecret: paOptions.encryptSecret,
          cookieId: paOptions.cookieId,
        })
      ).to.not.throw();
    });
  });
});
