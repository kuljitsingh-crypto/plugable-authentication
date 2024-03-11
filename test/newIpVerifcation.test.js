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
} = require("./testHelper");

const descriptionName = "#NewIpVerify";

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    let shortTok = null;
    const sendTokenFrIpValidation = (shortToken, tokenExpiresIn, user) => {
      shortTok = shortToken;
      console.log(shortTok, tokenExpiresIn);
    };
    context("new Ip address verification", function () {
      const paInstance = withOptionsPaInstanceCreator({
        uri: paOptions.uri,
        collection: paOptions.collectionName,
        jwtSecret: paOptions.jwtSecret,
        encryptSecret: paOptions.encryptSecret,
        cookieId: paOptions.cookieId,
        tokenSenderFrIpValidationCb: sendTokenFrIpValidation,
      })();
      const middleware = paInstance.middlewares();
      it("should have login middleware", function () {
        expect(middleware)
          .to.have.property("loginMiddleware")
          .that.is.a("function");
      });
      it("should have newIpAddrCheck middleware", function () {
        expect(middleware)
          .to.have.property("newIpAddrCheckMiddleware")
          .that.is.a("function");
      });
      it('should throw error "You\'re tring to login with different IP address.Please allow this, if you want to countinue."', function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ userIp: userIpAddress.ip2 });
        const { email, password } = getTestUserEmailPwdCredential();
        express
          .postHandler(loginMiddleware, { email, password })()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "You're tring to login with different IP address.Please allow this, if you want to countinue."
            );
            done();
          });
      });
      it('should throw error "Cannot add new IP address. Missing a required value."', function (done) {
        const { newIpAddrCheckMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ userIp: userIpAddress.ip2 });
        express
          .postHandler(newIpAddrCheckMiddleware)()
          .then(() => {
            expect(express.getResponseStatus).to.throw(
              Error,
              "Cannot add new IP address. Missing a required value."
            );
            done();
          });
      });
      it("should add New Ip addr to db", function (done) {
        const { newIpAddrCheckMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ userIp: userIpAddress.ip2 });
        express
          .postHandler(newIpAddrCheckMiddleware, { token: shortTok })()
          .then(() => {
            const resp = express.getResponseStatus();
            if (resp.toLowerCase() !== "ok") {
              return;
            }

            done();
          });
      });
      it("should logged in user with email", function (done) {
        const { loginMiddleware } = paInstance.middlewares();
        const express = dummyExpress({ userIp: userIpAddress.ip2 });
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
            expect(user).to.a("object");
            expect(user).to.have.property("email").that.is.equal(email);
            done();
          });
      });
    });
  }
});
