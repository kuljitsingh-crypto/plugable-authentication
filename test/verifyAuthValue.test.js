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

const descriptionName = "#VerifyAuthValue";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null,
      validationToken = null;
    context("verify auth value", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
      })();
      const middleware = paInstance.middlewares();
      it("should have generate auth verification token middleware", function () {
        expect(middleware)
          .to.have.property("generateTokenForAuthVerificationMiddleware")
          .that.is.a("function");
      });
      it("should have validate auth verification token middleware", function () {
        expect(middleware)
          .to.have.property("validateTokenForAuthVerificationMiddleware")
          .that.is.a("function");
      });
      it("should throw error '\"auth\" is required.'", function (done) {
        const { generateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(generateTokenForAuthVerificationMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"auth" is required.'
            );
            done();
          });
      });
      it("should generate validation token", function (done) {
        const { generateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(generateTokenForAuthVerificationMiddleware, {
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
        const { validateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(validateTokenForAuthVerificationMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"auth" is required.'
            );
            done();
          });
      });
      it("should throw error '\"token\" is required.'", function (done) {
        const { validateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(validateTokenForAuthVerificationMiddleware, {
            auth: email,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"token" is required.'
            );
            done();
          });
      });
      it("should throw error 'User's email does not match with requested one. Please double check and try again.'", function (done) {
        const { validateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();

        const { email } = getTestUserEmailOtpCredential();

        express
          .postHandler(validateTokenForAuthVerificationMiddleware, {
            auth: email,
            token: validationToken,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "User's email does not match with requested one. Please double check and try again."
            );
            done();
          });
      });
      it("should throw error 'Auth token verification failed. Try again later.'", function (done) {
        const { validateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(validateTokenForAuthVerificationMiddleware, {
            auth: email,
            token: Math.random().toString(),
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Auth token verification failed. Try again later."
            );
            done();
          });
      });
      it("should verify user", function (done) {
        const { validateTokenForAuthVerificationMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(validateTokenForAuthVerificationMiddleware, {
            auth: email,
            token: validationToken,
          })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express.getUserDetails();
            expect(user).to.a("object");
            expect(user).to.have.property("email", email);
            expect(user).to.have.property("isVerified").to.equals(true);
            done();
          });
      });
    });
  }
});
