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
  getTestUserPhoneOtpCredential,
  paOptionsForPhone,
  getTestUserPhoneOtpCredential2,
} = require("./testHelper");

const descriptionName = "#ChangePhoneAuthValue";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let csrfToken = null;
    const otpValidationCb = (reqestBody, user) => {
      const { otp } = reqestBody;
      console.log(otp);
      return user.metadata.otp === otp;
    };
    context("change phone auth value", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
        ...paOptionsForPhone,
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
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: phoneNumber,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"newAuth" is required.'
            );
            done();
          });
      });

      it("should throw error 'Your old and new authentication information must different.'", function (done) {
        const { changeAuthenticationValueMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: phoneNumber,
            newAuth: phoneNumber,
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
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        const { phoneNumber: newAuth } = getTestUserPhoneOtpCredential2();
        express
          .postHandler(changeAuthenticationValueMiddleware, {
            oldAuth: phoneNumber,
            newAuth,
          })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Your CSRF token is invalid."
            );
            done();
          });
      });

      it("should throw error 'The phoneNumber you provided don't match our records. Please double-check and try again.'", function (done) {
        const { changeAuthenticationValueMiddleware, loginMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { phoneNumber, otp } = getTestUserPhoneOtpCredential();
        const { phoneNumber: newAuth } = getTestUserPhoneOtpCredential2();
        express
          .postHandler(loginMiddleware, { phoneNumber, otp })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "The phoneNumber you provided don't match our records. Please double-check and try again."
            );
            done();
          });
      });
      it("should throw error 'The phoneNumber you provided don't match our records. Please double-check and try again.'", function (done) {
        const { changeAuthenticationValueMiddleware, loginMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { phoneNumber, otp } = getTestUserPhoneOtpCredential();
        const { phoneNumber: newAuth } = getTestUserPhoneOtpCredential2();
        express
          .postHandler(loginMiddleware, { phoneNumber, otp })({
            customValidation: otpValidationCb,
            validationLabelName: "otp",
          })
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
              oldAuth: phoneNumber,
              newAuth,
            })();
          })
          .then(() => {
            expect(express2.getResponseStatus).to.throw(
              Error,
              "The phoneNumber you provided don't match our records. Please double-check and try again."
            );
            done();
          });
      });
      it("should throw error 'Change user phone number'", function (done) {
        const { changeAuthenticationValueMiddleware, loginMiddleware } =
          paInstance.middlewares();
        const express = dummyExpress();
        let express2;
        const { phoneNumber, otp } = getTestUserPhoneOtpCredential();
        const { phoneNumber: newAuth } = getTestUserPhoneOtpCredential2();
        express
          .postHandler(loginMiddleware, { phoneNumber, otp })({
            customValidation: otpValidationCb,
            validationLabelName: "otp",
          })
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
              oldAuth: phoneNumber,
              newAuth,
              otp,
            })({
              customValidation: otpValidationCb,
              validationLabelName: "otp",
            });
          })
          .then(() => {
            const resp = express2.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express2.getUserDetails();
            expect(user).to.a("object");
            expect(user).to.have.property("phoneNumber").that.is.equal(newAuth);
            done();
          });
      });
    });
  }
});
