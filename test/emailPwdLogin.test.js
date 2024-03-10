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
  paOptionsForOtp,
  getTestUserEmailOtpCredential,
  getRandomeDigitOfLen,
  userIpAddress,
  userCsrfToken,
} = require('./testHelper');

const descriptionName = '#EmailPwdLogin';

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    context('Log in with email and password ', function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
      })();
      const middleware = paInstance.middlewares();
      it('should have login middleware', function () {
        expect(middleware)
          .to.have.property('loginMiddleware')
          .that.is.a('function');
      });
      it('should throw error \'"email" is required.\'', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(loginMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"email" is required.'
            );
            done();
          });
      });
      it('should throw error \'"password" is required.\'', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(loginMiddleware, { email })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"password" is required.'
            );
            done();
          });
      });
      it('should throw error "You\'re tring to login with different IP address.Please allow this, if you want to countinue."', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ userIp: userIpAddress.ip2 });
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(loginMiddleware, { email, password })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "You're tring to login with different IP address.Please allow this, if you want to countinue."
            );
            done();
          });
      });
      it('should logged in user with email', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(loginMiddleware, { email, password })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== 'ok') {
              return;
            }
            const user = express.getUserDetails();
            csrfToken = user.csrfToken;
            expect(user).to.a('object');
            expect(user).to.have.property('email').that.is.equal(email);
            done();
          });
      });
      it('should have logout middleware', function () {
        expect(middleware)
          .to.have.property('logoutMiddleware')
          .that.is.a('function');
      });
      it("should throw error 'Your CSRF token is invalid.'", function (done) {
        const { logoutMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(logoutMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              'Your CSRF token is invalid.'
            );
            done();
          });
      });
      it('should logged out user', function (done) {
        const { logoutMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ csrfToken: csrfToken });
        express
          .postHandler(logoutMiddleware)()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== 'ok') {
              return;
            }
            const user = express.getUserDetails();
            expect(user).to.a('object');
            done();
          });
      });
    });
  }
});
