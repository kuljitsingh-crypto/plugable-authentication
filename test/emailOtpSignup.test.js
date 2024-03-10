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
} = require('./testHelper');

const descriptionName = '#EmailOtpSignup';

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    context('Sign up with email and otp ', function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
        ...paOptionsForOtp,
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
      it('should create new user in database or throw error when user sign up with same email', function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailOtpCredential();
        let userOtp = null;
        const addOtpInMetadata = (requestBody) => {
          const otp = getRandomeDigitOfLen(6);
          userOtp = otp;
          return { otp };
        };
        express
          .postHandler(signupMiddleware, { email })({
            metadataCb: addOtpInMetadata,
          })
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== 'ok') {
              return;
            }
            const user = express.getUserDetails();

            expect(user).to.a('object');
            expect(user).to.have.property('email').that.is.equal(email);
            expect(user.metadata).to.a('object');
            expect(user.metadata)
              .to.have.property('otp')
              .that.is.equal(userOtp);
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
