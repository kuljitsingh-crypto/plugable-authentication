const { expect } = require('chai');
const {
  withOptionsPaInstanceCreator,
  paOptions,
  requestMethod,
  dummyExpress,
  getTestUserEmailPwdCredential,
  extraPaOptions,
  getTestUserNamePwdCredential,
  getFailedTestUserNamePwdCredential,
  isSingleTestFileExceutionMatchFile,
} = require('./testHelper');

const descriptionName = '#EmailPwdSignup';

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    context('Sign up with default options', function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
      })();
      const middleware = paInstance.middlewares();
      it('should have signup middleware', function () {
        expect(middleware)
          .to.have.property('signupMiddleware')
          .that.is.a('function');
      });
      it('should throw error \'"email" is required.\'', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(signupMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"email" is required.'
            );
            done();
          });
      });
      it('should throw error \'"email" must be string.\'', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(signupMiddleware, { email: 1235 })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"email" must be a string.'
            );
            done();
          });
      });
      it('should throw error \'"password" is required.\'', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(signupMiddleware, { email })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"password" is required.'
            );
            done();
          });
      });
      it('should throw error \'"password" must be a string.\'', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(signupMiddleware, {
            email,
            password: 12345,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"password" must be a string.'
            );
            done();
          });
      });
      it('should throw error \'"password" with value "12345" fails to match the "Must be between 8 and 256 characters" pattern.\'', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(signupMiddleware, {
            email,
            password: '12345',
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"password" with value "12345" fails to match the "Must be between 8 and 256 characters" pattern.'
            );
            done();
          });
      });
      it('should create new user in database or throw error when user sign up with same email', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const userInput = {
          ...getTestUserEmailPwdCredential(),
        };
        express
          .postHandler(signupMiddleware, userInput)()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== 'ok') {
              return;
            }
            const user = express.getUserDetails();
            expect(user).to.a('object');
            expect(user)
              .to.have.property('email')
              .that.is.equal(userInput.email);
            done();
          })
          .catch((err) => {
            const msg = err.message;
            expect(msg).to.equal(
              'User with given email already exists. Please log in with your registered email.'
            );
            done();
          });
      });
    });
  }
});
