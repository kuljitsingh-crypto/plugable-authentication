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
  paOptionsForPhone,
  getTestUserPhoneOtpCredential,
} = require("./testHelper");

const descriptionName = "#PhoneOtpSignup";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    context("Sign up with phone and otp ", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
        ...paOptionsForPhone,
      })();
      const middleware = paInstance.middlewares();
      it("should have signup middleware", function () {
        expect(middleware)
          .to.have.property("signupMiddleware")
          .that.is.a("function");
      });
      it("should throw error '\"phoneNumber\" is required.'", function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        express
          .postHandler(signupMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              '"phoneNumber" is required.'
            );
            done();
          });
      });
      it("should create new user in database or throw error when user sign up with same phoneNumber", function (done) {
        const { signupMiddleware } = paInstance.middlewares();
        const express = dummyExpress();
        const { phoneNumber } = getTestUserPhoneOtpCredential();
        let userOtp = null;
        const addOtpInMetadata = (requestBody) => {
          const otp = getRandomeDigitOfLen(6);
          userOtp = otp;
          return { otp };
        };
        express
          .postHandler(signupMiddleware, { phoneNumber })({
            metadataCb: addOtpInMetadata,
          })
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }
            const user = express.getUserDetails();

            expect(user).to.a("object");
            expect(user)
              .to.have.property("phoneNumber")
              .that.is.equal(phoneNumber);
            expect(user.metadata).to.a("object");
            expect(user.metadata)
              .to.have.property("otp")
              .that.is.equal(userOtp);
            done();
          })
          .catch((err) => {
            const msg = err.message;

            expect(msg).to.equal(
              "User with given phoneNumber already exists. Please log in with your registered phoneNumber."
            );
            done();
          });
      });
    });
  }
});
