const { expect } = require('chai');
const {
  withOptionsPaInstanceCreator,
  paOptions,
  dummyExpress,
  extraPaOptions,
  getTestUserNamePwdCredential,
  isSingleTestFileExceutionMatchFile,
} = require('./testHelper');

const descriptionName = '#DefaultValidationUsername';

describe(descriptionName, function () {
  const shouldExecute = isSingleTestFileExceutionMatchFile(descriptionName);
  if (shouldExecute) {
    context(
      'signup middlware for username and password with default validation for username',
      function () {
        const paInstance = withOptionsPaInstanceCreator({
          uri: paOptions.uri,
          collection: paOptions.collectionName,
          jwtSecret: paOptions.jwtSecret,
          encryptSecret: paOptions.encryptSecret,
          cookieId: paOptions.cookieId,
          authKeyName: extraPaOptions.authKeyName,
          disableEmailValidation: extraPaOptions.disableEmailValidation,
        })();
        const { signupMiddleware } = paInstance.middlewares();
        it('should throw error "username" is required.', function (done) {
          const express = dummyExpress();
          express
            .postHandler(signupMiddleware, {})()
            .then(() => {
              const resp = express.getResponseStatus();
            })
            .catch((err) => {
              const msg = err.message;
              expect(msg).to.equal('"username" is required.');
              done();
            });
        });
        it('should throw error "password" is required.', function (done) {
          const express = dummyExpress();
          const userInput = {
            username: getTestUserNamePwdCredential().username,
          };
          express
            .postHandler(signupMiddleware, userInput)()
            .then(() => {
              const resp = express.getResponseStatus();
            })
            .catch((err) => {
              const msg = err.message;
              expect(msg).to.equal('"password" is required.');
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
