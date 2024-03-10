# Plugable Authentication
The PlugableAuthentication module offers middleware functions for various authentication tasks within Node.js applications, particularly in conjunction with Express.js. These middleware functions handle user authentication, password management, token generation, and validation, providing a flexible and customizable solution for authentication and security requirements.

# Features
- **Plugable Middleware Functions**: Easily integrate authentication-related middleware functions into your Express.js application to manage authentication and security tasks.

- **Customizable Authentication**: Customize authentication methods according to your specific requirements. For example, implement phone number-OTP authentication, email-OTP authentication, username-password authentication, and more.

- **CSRF Token Generation and Validation**: Built-in functionality for generating and validating CSRF tokens to prevent cross-site request forgery attacks.

- **IP Address Mismatch Checking**: Validate IP addresses to detect potential unauthorized access attempts, enhancing security against unauthorized users.

- **Token Generation for New IP Addresses**: Automatically generate tokens when users attempt to access the application from new IP addresses, enhancing security measures.

## Installation
```bash
npm install plugable-authentication
```
or
```bash
yarn add plugable-authentication
```

### Usage Initialization
```javascript
const { PlugableAuthentication } = require('plugable-authentication');

// required values for PlugableAuthentication
const requiredParams={
  collection: 'db_collection_name',
  uri: 'mongo_db_uri',
  jwtSecret: 'your_jwt_secret',
  encryptSecret: 'your_encryption_secret',
  cookieId: 'your_cookie_id',
}
//optional values (based on your authentication logic) are:
const optionalParams = {
  authKeyName:
    "Default: 'email'. It will be used as the schema name for the database. The package will also search for this key name in the req.body during login and signup.",
  secndAuthKeyName:
    "Default: 'otp'. It will be used when disablePasswordValidation = true. The package will search for this key name in the req.body during login and signup.",
  newIpAddrTokenName:
    "Default: 'token'. It will be used to get the token value for a new IP address.",
  disablePasswordValidation:
    "Default: 'false'. Useful when you want authentication like phone number and OTP. In this case, password validation is not required.",
  disableEmailValidation:
    "Default: 'false'. Useful when you don't want to use email-password based authentication, rather you want something like username and password.",
  disableCSRFTokenValidation:
    "Default: 'false'. It disables CSRF token validation if you don't want to use this feature.",
  disableIpMismatchValidation:
    "Default: 'false'. It will disable IP mismatch validation if you don't want to use this feature.",
  authKeyValidationPattern:
    "Default: null. If you want to use your own validation for the authentication value email, then write your own validation logic like this: '^[a-zA-Z0-9]+_[a-zA-Z0-9]+$'. If you want this feature, make sure disableEmailValidation=true.",
  authKeyValidationName:
    'It is used when disableEmailValidation=true and authKeyValidationPattern != null. Default: \'"Must be valid characters"\'. If you want to write your custom message, please change it.',
  passwordValidationPattern:
    "It is used when disablePasswordValidation=false. Default: '^[a-zA-Z0-9@$!%*?&^#~_+-]{8,256}$. If you want to write your custom validation logic, please change it.",
  passwordValidationName:
    'Default: \'"Must be between 8 and 256 characters". If you want to write your custom message, please change it.',
  jwtOptions:
    "Default: '{ algorithm: 'HS256', noTimestamp: false, expiresIn: '1h', notBefore: '0s' }'. Change as per your need.",
  jwtOptnFrIpValidation:
    "Default: null. Example: { expiresIn: '10h'/'7d' }. It is used to modify the token generated during IP address mismatch. Only allowed key is expiresIn. By default, the token expires in 1 day.",
  tokenSenderFrIpValidationCb:
    'Default: null. It is used when someone tries to login with a different IP address and IP mismatch validation is enabled. Then this function will be called with token and user details. Function format is like this: (shortToken: string, user: { email: string, id: string, refreshToken: string, csrfToken: string, metadata?: object, password?: string, browser: string, ipAddr: string }) => Promise<void>.',
  csrfTokenExpireTime:
    "Default: null. Example: '10h'/'7d'. It is used to modify the token expires time. By default, the token expires in 1 day.",
  verifyAuthKeyOnCreation:
    'Default: false. If you want to mark your authentication key (email) as verified on creation, set as true.',
};

const authInstance = new PlugableAuthentication({
  ...requiredParams,
  ...optionalParams
});
```
### Example usage:
``` javascript

const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();

const {
  signupMiddleware,
  loginMiddleware,
  newIpAddrCheckMiddleware,
  logoutMiddleware,
  newCsrfTokenMiddleware,
  verifyUserTokenMiddleware,
  changeAuthenticationValueMiddleware,
  changePasswordMiddleware,
  resetPasswordMiddleware,
  resetPasswordVerifyMiddleware,
  generateTokenForAuthVerificationMiddleware,
  validateTokenForAuthVerificationMiddleware,
} = authInstance.middlewares();

app.use(express.json({ limit: '200mb' }));
app.use(cookieParser());

// It is required to read user Ip address.
app.set('trust proxy', true);

app.post('/signup', signupMiddleware(), (req, res) => {
  try {
    //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
    res.sendStatus(200);
  } catch (e) {
    console.error(e);
  }
});

app.post('/login', loginMiddleware(), (req, res) => {
  try {
     //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
    res.sendStatus(200);
  } catch (e) {
    console.error(e);
  }
});

app.post('/new-ip-addr', newIpAddrCheckMiddleware(), (req, res) => {
  res.sendStatus(200);
});

app.post('/new-csrf-token', newCsrfTokenMiddleware(), (req, res) => {
     //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
  res.status(200).send({ csrfToken: req.csrfToken });
});

app.get('/logout', logoutMiddleware(), (req, res) => {
   //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
  res.sendStatus(200);
});

app.post('/userDetails', verifyUserTokenMiddleware(), (req, res) => {
   //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
  res.sendStatus(200);
});

app.post('/change-email', changeAuthenticationValueMiddleware(), (req, res) => {
   //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
  res.sendStatus(200);
});

app.post('/change-pwd', changePasswordMiddleware(), (req, res) => {
   //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);console.log(req.user);
  res.sendStatus(200);
});

app.post('/reset-pwd', resetPasswordMiddleware(), (req, res) => {
  //attach user details and validation token in request object
  console.log(req.validationToken, req.user);
  res.sendStatus(200);
});

app.post('/reset-pwd-verify', resetPasswordVerifyMiddleware(), (req, res) => {
   //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
  res.sendStatus(200);
});

app.post(
  '/auth-verify-gen',
  generateTokenForAuthVerificationMiddleware(),
  (req, res) => {
    //attach user details and validation token in request object
    console.log(req.validationToken, req.user);
    res.sendStatus(200);
  }
);

app.post(
  '/auth-verify',
  validateTokenForAuthVerificationMiddleware(),
  (req, res) => {
     //attach user details and csrf token in request object
    console.log(req.user,req.csrfToken);
    res.sendStatus(200);
  }
);


```


### Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request.