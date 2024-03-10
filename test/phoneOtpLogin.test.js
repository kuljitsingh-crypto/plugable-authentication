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
  paOptionsForPhone,
  getTestUserPhoneOtpCredential,
} = require('./testHelper');

const descriptionName = '#PhoneOtpLogin';

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    const otpValidationCb = (reqestBody, user) => {
      const { otp } = reqestBody;
      return user.metadata.otp === otp;
    };
    context('Log in with phone and otp ', function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
        ...paOptionsForPhone,
      })();
      const middleware = paInstance.middlewares();
      it('should have login middleware', function () {
        expect(middleware)
          .to.have.property('loginMiddleware')
          .that.is.a('function');
      });
      it('should throw error \'"phoneNumber" is required.\'', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(loginMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"phoneNumber" is required.'
            );
            done();
          });
      });
      it("should throw error 'The phoneNumber you provided don't match our records. Please double-check and try again.'", function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        express
          .postHandler(loginMiddleware, { phoneNumber })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "The phoneNumber you provided don't match our records. Please double-check and try again."
            );
            done();
          });
      });
      it('should throw error \'"otp" is not allowed to be empty.', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        express
          .postHandler(loginMiddleware, { phoneNumber, otp: '' })({
            customValidation: otpValidationCb,
          })
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"otp" is not allowed to be empty.'
            );
            done();
          });
      });
      it('should throw error "The phoneNumber and otp you provided don\'t match our records. Please double-check and try again."', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        const otp = getRandomeDigitOfLen(6);
        express
          .postHandler(loginMiddleware, { phoneNumber, otp: otp })({
            customValidation: otpValidationCb,
            validationLabelName: 'otp',
          })
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "The phoneNumber and otp you provided don't match our records. Please double-check and try again."
            );
            done();
          });
      });
      it('should throw error "You\'re tring to login with different IP address.Please allow this, if you want to countinue."', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ userIp: userIpAddress.ip2 });
        const { phoneNumber, otp } = getTestUserPhoneOtpCredential();
        express
          .postHandler(loginMiddleware, { phoneNumber, otp })({
            customValidation: otpValidationCb,
            validationLabelName: 'otp',
          })
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
        const { phoneNumber, otp } = getTestUserPhoneOtpCredential();
        express
          .postHandler(loginMiddleware, { phoneNumber, otp })({
            customValidation: otpValidationCb,
            validationLabelName: 'otp',
          })
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== 'ok') {
              return;
            }
            const user = express.getUserDetails();
            csrfToken = user.csrfToken;
            expect(user).to.a('object');
            expect(user)
              .to.have.property('phoneNumber')
              .that.is.equal(phoneNumber);
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
