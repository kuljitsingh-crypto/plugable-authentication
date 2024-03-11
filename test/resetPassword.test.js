const { expect } = require("chai");
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
  delayPromise,
  userPwd,
} = require("./testHelper");

const descriptionName = "#ResetPwdValue";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null,
      validationToken = null;
    context("reset password value", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
      })();
      const middleware = paInstance.middlewares();
      it("should have resetPwd middleware", function () {
        expect(middleware)
          .to.have.property("resetPasswordMiddleware")
          .that.is.a("function");
      });
      it("should have resetPwdVerify middleware", function () {
        expect(middleware)
          .to.have.property("resetPasswordVerifyMiddleware")
          .that.is.a("function");
      });
      it("should throw error '\"auth\" is required.'", function (done) {
        const { resetPasswordMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(resetPasswordMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"auth" is required.'
            );
            done();
          });
      });
      it("should generate validation token", function (done) {
        const { resetPasswordMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(resetPasswordMiddleware, {
            auth: email,
          })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express.getUserDetails();
            validationToken = express.getValidationToken();
            const tokenex = express.getTokenExpiryTime();
            expect(user).to.a("object");
            expect(user).to.have.property("email").to.equal(email);
            expect(validationToken).to.a("string");
            expect(tokenex).to.a("Date");
            done();
          });
      });
      it("should throw error '\"auth\" is required.'", function (done) {
        const { resetPasswordVerifyMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(resetPasswordVerifyMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"auth" is required.'
            );
            done();
          });
      });
      it("should throw error '\"token\" is required.'", function (done) {
        const { resetPasswordVerifyMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(resetPasswordVerifyMiddleware, { auth: email })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"token" is required.'
            );
            done();
          });
      });
      it("should throw error '\"newPassword\" is required.'", function (done) {
        const { resetPasswordVerifyMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(resetPasswordVerifyMiddleware, {
            auth: email,
            token: validationToken,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"newPassword" is required.'
            );
            done();
          });
      });
      it("should change user password", function (done) {
        const { resetPasswordVerifyMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(resetPasswordVerifyMiddleware, {
            auth: email,
            token: validationToken,
            newPassword: password,
          })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express.getUserDetails();
            expect(user).to.a("object");
            expect(user).to.have.property("email", email);
            done();
          });
      });
    });
  }
});
