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

const descriptionName = "#verifyTokenWithDisableCsrfTokenValidation";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    context(
      "verify use cookie token with csrf token validation disabled",
      function () {
        const { disableCSRFTokenValidation } = disablePaOptions;
        const paInstance = withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
          encryptSecret: paOptions.encryptSecret,
          cookieId: paOptions.cookieId,
          disableCSRFTokenValidation,
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

        it("should throw error 'Looks like you tried to connect with a different IP Address.'", function (done) {
          const { verifyUserTokenMiddleware, loginMiddleware } =
            paInstance.middlewares();
          const express = dummyExpress({ userIp: userIpAddress.ip2 });

          express
            .postHandler(verifyUserTokenMiddleware)()
            .then(() => {
              expect(express.getResponseStatus).to.throw(
                Error,
                "Looks like you tried to connect with a different IP Address."
              );
              done();
            });
        });

        it("should show user details", function (done) {
          const { verifyUserTokenMiddleware, loginMiddleware } =
            paInstance.middlewares();
          const express = dummyExpress();
          const { email } = getTestUserEmailPwdCredential();
          express
            .postHandler(verifyUserTokenMiddleware)()
            .then(() => {
              const resp = express.getResponseStatus();
              if (resp.toLowerCase() !== "ok") {
                return;
              }
              const user = express.getUserDetails();
              expect(user).to.a("object");
              expect(user).to.have.property("email").that.is.equal(email);
              done();
            });
        });
      }
    );
  }
});
