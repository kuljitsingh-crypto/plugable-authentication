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
  disablePaOptions,
} = require("./testHelper");

const descriptionName = "#verifyTokenWithDisableIpMismatchValidation";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    context(
      "verify use cookie token with ip mismatch validation disabled ",
      function () {
        const { disableIpMismatchValidation } = disablePaOptions;
        const paInstance = withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
          encryptSecret: paOptions.encryptSecret,
          cookieId: paOptions.cookieId,
          disableIpMismatchValidation,
        })();
        const middleware = paInstance.middlewares();
        it("should have verifyUser  middleware", function () {
          expect(middleware)
            .to.have.property("verifyUserTokenMiddleware")
            .that.is.a("function");
        });
        it("should throw error 'Cookie is either invalid or does not exist. Please check and try again.'", function (done) {
          const { verifyUserTokenMiddleware } = paInstance.middlewares();
          const express = dummyExpress({ disableUserCookie: true });
          express
            .postHandler(verifyUserTokenMiddleware)()
            .then(() => {
              expect(express.getResponseStatus).to.throw(
                Error,
                "Cookie is either invalid or does not exist. Please check and try again."
              );
              done();
            });
        });
        it("should throw error 'Your CSRF token is invalid.'", function (done) {
          const { verifyUserTokenMiddleware } = paInstance.middlewares();
          const express = dummyExpress();
          express
            .postHandler(verifyUserTokenMiddleware)()
            .then(() => {
              expect(express.getResponseStatus).to.throw(
                Error,
                "Your CSRF token is invalid."
              );
              done();
            });
        });
        it("should throw error 'The email and password you provided don't match our records. Please double-check and try again.'", function (done) {
          const { verifyUserTokenMiddleware, loginMiddleware } =
            paInstance.middlewares();
          const express = dummyExpress();
          let express2;
          const { email, password } = getTestUserEmailPwdCredential();

          express
            .postHandler(loginMiddleware, { email, password })()
            .then(() => {
              expect(express.getResponseStatus).to.throw(
                Error,
                "The email and password you provided don't match our records. Please double-check and try again."
              );
              done();
            });
        });

        it("should show user details", function (done) {
          const { verifyUserTokenMiddleware, loginMiddleware } =
            paInstance.middlewares();
          const express = dummyExpress({ userIp: userIpAddress.ip2 });
          let express2;
          const { email } = getTestUserEmailPwdCredential();
          const { pwd2 } = userPwd;
          express
            .postHandler(loginMiddleware, { email, password: pwd2 })()
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
              return express2.postHandler(verifyUserTokenMiddleware)();
            })
            .then(() => {
              const resp = express2.getResponseStatus();
              if (resp.toLowerCase() !== "ok") {
                return;
              }
              const user = express2.getUserDetails();
              expect(user).to.a("object");
              expect(user).to.have.property("email").that.is.equal(email);
              done();
            });
        });
      }
    );
  }
});
