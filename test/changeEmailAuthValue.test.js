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
} = require("./testHelper");

const descriptionName = "#ChangeEmailAuthValue";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    context("change email auth value", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
      })();
      const middleware = paInstance.middlewares();
      it("should have changeAuth middleware", function () {
        expect(middleware)
          .to.have.property("changeAuthenticationValueMiddleware")
          .that.is.a("function");
      });
      it("should throw error '\"oldAuth\" is required.'", function (done) {
        const { changeAuthenticationValueMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(changeAuthenticationValueMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"oldAuth" is required.'
            );
            done();
          });
      });
      it("should throw error '\"newAuth\" is required.'", function (done) {
        const { changeAuthenticationValueMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: email,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"newAuth" is required.'
            );
            done();
          });
      });
      it("should throw error '\"password\" is required.'", function (done) {
        const { changeAuthenticationValueMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        const { email: newAuth } = getTestUserEmailOtpCredential();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: email,
            newAuth,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"password" is required.'
            );
            done();
          });
      });
      it("should throw error 'Your old and new authentication information must different.'", function (done) {
        const { changeAuthenticationValueMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: email,
            newAuth: email,
            password,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Your old and new authentication information must different."
            );
            done();
          });
      });
      it("should throw error 'Your CSRF token is invalid.'", function (done) {
        const { changeAuthenticationValueMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { email, password } = getTestUserEmailPwdCredential();
        const { email: newAuth } = getTestUserEmailOtpCredential();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: email,
            newAuth,
            password,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Your CSRF token is invalid."
            );
            done();
          });
      });
      it("should 'Change user email address'", function (done) {
        const { changeAuthenticationValueMiddleware, loginMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { email, password } = getTestUserEmailPwdCredential();
        const { email: newAuth } = getTestUserEmailOtpCredential();
        express
          .postHandler(loginMiddleware, { email, password })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express.getUserDetails();
            csrfToken = user.csrfToken;
            return delayPromise();
          })
          .then(() => {
            express2 = dummyExpress({ csrfToken });
            return express2.postHandler(changeAuthenticationValueMiddleware, {
              oldAuth: email,
              newAuth,
              password,
            })();
          })
          .then(() => {
            const resp = express.getResponseStatus();
            console.log(resp.toString());
            if (resp.toLowerCase() !== "ok") {
              return;
            }

            const user = express2.getUserDetails();
            expect(user).to.a("object");
            expect(user).to.have.property("email").that.is.equal(newAuth);
            done();
          });
      });
    });
  }
});
