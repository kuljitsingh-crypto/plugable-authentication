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

const descriptionName = "#NewCsrfToken";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    context("new csrf token ", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
      })();
      const middleware = paInstance.middlewares();
      it("should have newCsrkToken  middleware", function () {
        expect(middleware)
          .to.have.property("newCsrfTokenMiddleware")
          .that.is.a("function");
      });
      it("should throw error 'Cookie is either invalid or does not exist. Please check and try again.'", function (done) {
        const { newCsrfTokenMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ disableUserCookie: true });
        express
          .postHandler(newCsrfTokenMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Cookie is either invalid or does not exist. Please check and try again."
            );
            done();
          });
      });
      it("should create Csrf token", function (done) {
        const { newCsrfTokenMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { email } = getTestUserEmailPwdCredential();
        const { pwd2 } = userPwd;
        express
          .postHandler(newCsrfTokenMiddleware, { email, password: pwd2 })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express.getUserDetails();
            csrfToken = user.csrfToken;
            expect(user).to.a("object");
            expect(user).to.have.property("email").that.is.equal(email);
            expect(csrfToken).to.a("string");
            done();
          });
      });
    });
  }
});
