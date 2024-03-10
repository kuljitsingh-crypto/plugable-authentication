const { expect } = require('chai');
const {
  withOptionsPaInstanceCreator,
  paOptions,
  dummyExpress,
  extraPaOptions,
  getTestUserNamePwdCredential,
  getFailedTestUserNamePwdCredential,
  isSingleTestFileExceutionMatchFile,
} = require('./testHelper');
const descriptionName = '#CustomValidationUsernameSignup';

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    context(
      'signup middlware for username and password with validation for username',
      function () {
        const paInstance = withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
          encryptSecret: paOptions.encryptSecret,
          cookieId: paOptions.cookieId,
          authKeyName: extraPaOptions.authKeyName,
          disableEmailValidation: extraPaOptions.disableEmailValidation,
          authKeyValidationName: extraPaOptions.authKeyValidationName,
          authKeyValidationPattern: extraPaOptions.authKeyValidationPattern,
        })();
        const { signupMiddleware } = paInstance.middlewares();
        it('should throw error "username" with value "testuser" fails to match the user name like "abc_dhe45" required pattern', function (done) {
          const express = dummyExpress();
          const userInput = {
            ...getFailedTestUserNamePwdCredential(),
          };
          express
            .postHandler(signupMiddleware, userInput)()
            .then(() => {
              const resp = express.getResponseStatus();
              if (resp.toLowerCase() !== 'ok') {
                return;
              }
              const user = express.getUserDetails();
              expect(user).to.a('object');
              expect(user)
                .to.have.property('username')
                .that.is.equal(userInput.username);
              done();
            })
            .catch((err) => {
              const msg = err.message;
              expect(msg).to.equal(
                '"username" with value "testuser" fails to match the user name like "abc_dhe45" required pattern.'
              );
              done();
            });
        });
        it('should create new user in database or throw error when user sign up with same username', function (done) {
          const { signupMiddleware } = paInstance.middlewares();
          const express = dummyExpress();
          const userInput = {
            ...getTestUserNamePwdCredential(),
          };
          express
            .postHandler(signupMiddleware, userInput)()
            .then(() => {
              const resp = express.getResponseStatus();
              if (resp.toLowerCase() !== 'ok') {
                return;
              }
              const user = express.getUserDetails();
              expect(user).to.a('object');
              expect(user)
                .to.have.property('username')
                .that.is.equal(userInput.username);
              done();
            })
            .catch((err) => {
              const msg = err.message;
              expect(msg).to.equal(
                'User with given username already exists. Please log in with your registered username.'
              );
              done();
            });
        });
      }
    );
  }
});
