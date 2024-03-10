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

const descriptionName = "#ChangePwdValue";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    context("change password value", function () {
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
          .to.have.property("changePasswordMiddleware")
          .that.is.a("function");
      });
      it("should throw error '\"auth\" is required.'", function (done) {
        const { changePasswordMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(changePasswordMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"auth" is required.'
            );
            done();
          });
      });
      it("should throw error '\"oldPassword\" is required.'", function (done) {
        const { changePasswordMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email } = getTestUserEmailPwdCredential();
        express
          .postHandler(changePasswordMiddleware, {
            auth: email,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"oldPassword" is required.'
            );
            done();
          });
      });
      it("should throw error '\"newPassword\" is required.'", function (done) {
        const { changePasswordMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(changePasswordMiddleware, {
            auth: email,
            oldPassword: password,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"newPassword" is required.'
            );
            done();
          });
      });
      // it("should throw error 'Your old and new authentication information must different.'", function (done) {
      //   const { changePasswordMiddleware } = paInstance.middlewares();
      //   const express = dummyExpress();
      //   const { email, password } = getTestUserEmailPwdCredential();
      //   express
      //     .postHandler(changePasswordMiddleware, {
      //       auth: email,
      //       oldPassword: password,
      //       newPassword: password,
      //     })()
      //     .then(() => {
      //       expect(express.getResponseStatus).to.throw(
      //         Error,
      //         "Your old and new authentication information must different."
      //       );
      //       done();
      //     });
      // });
      it("should throw error 'Your CSRF token is invalid.'", function (done) {
        const { changePasswordMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(changePasswordMiddleware, {
            auth: email,
            oldPassword: password,
            newPassword: password,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Your CSRF token is invalid."
            );
            done();
          });
      });
      it("should throw error 'New password must be different from previous one.'", function (done) {
        const { changePasswordMiddleware, loginMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { email, password } = getTestUserEmailPwdCredential();
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
            return express2.postHandler(changePasswordMiddleware, {
              auth: email,
              oldPassword: password,
              newPassword: password,
            })();
          })
          .then(() => {
            expect(express2.getResponseStatus).to.throw(
              Error,
              "New password must be different from previous one."
            );
            done();
          });
      });
      it("should 'Change user password'", function (done) {
        const { changePasswordMiddleware, loginMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { email, password } = getTestUserEmailPwdCredential();
        const { pwd2 } = userPwd;
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
            return express2.postHandler(changePasswordMiddleware, {
              auth: email,
              oldPassword: password,
              newPassword: pwd2,
            })();
          })
          .then(() => {
            const resp = express2.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express2.getUserDetails();
            expect(user).to.a("object");
            done();
          });
      });
    });
  }
});
