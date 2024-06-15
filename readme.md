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
  sendTokenForIpValidation:
    'Default: null. It is used when someone tries to login with a different IP address and IP mismatch validation is enabled. Then this function will be called with token and user details. Function format is like this: (shortToken: string, user: { email: string, id: string, refreshToken: string, csrfToken: string, metadata?: object, password?: string, browser: string, ipAddr: string }) => Promise<void>.',
  csrfTokenExpireTime:
    "Default: null. Example: '10h'/'7d'. It is used to modify the token expires time. By default, the token expires in 1 day.",
  verifyAuthKeyOnCreation:
    'Default: false. If you want to mark your authentication key (email) as verified on creation, set as true.',
  sanitizeObjectBeforeAdd: 'Default true. Sanitize metadata,privateData and publicData before adding to the database.',
 thirdPartyLoginOption - 'default empty object.
    "providerName" representing the name of third-party authentication providers (e.g., "google", "facebook",etc.),
   "isPasswordRequired" (default false): Indicates whether a password is required for the corresponding authentication provider,
   passwordValidationPattern" (default '^[a-zA-Z0-9@$!%*?&^#~_+-]{8,256}$'): Regex for validating passwords for the corresponding authentication provider,used only when "isPasswordRequired=true",
   "passwordValidationName" (default '"Must be valid characters"'): Message displayed when a password not match "passwordValidationPattern", used only when "isPasswordRequired=true".
   '

};

const authInstance = new PlugableAuthentication({
  ...requiredParams,
  ...optionalParams
});

```
### Example usage:
``` javascript

require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
const { PlugableAuthentication } = require("../index");
const { paOptions } = require("./helper");
const {
  googleAuthenticate,
  googleAuthenticateCallback,
} = require("./google-login");

const authInstance = new PlugableAuthentication({
  ...paOptions,
  sendTokenForIpValidation: (shortToken, tokenExpiresIn, user) => {
    console.log("ip token", shortToken, tokenExpiresIn, user);
  },
  thirdPartyLoginOption: { google: {} },
  disableCSRFTokenValidation: true,
});

const {
  signupMiddleware,
  loginMiddleware,
  newIpAddrCheckMiddleware,
  logoutMiddleware,
  newCsrfTokenMiddleware,
  verifyUserTokenMiddleware,
  getCurrentUserMiddleware,
  deleteCurrentUserMiddleware,
  changeAuthenticationValueMiddleware,
  changePasswordMiddleware,
  resetPasswordMiddleware,
  resetPasswordVerifyMiddleware,
  generateTokenForAuthVerificationMiddleware,
  validateTokenForAuthVerificationMiddleware,
  thirdPartyLoginMiddleware,
} = authInstance.middlewares();


const {
  getUserDetails,
  updateUserDetails,
  removeKeysFromUserDetails,
  getUsersDetails,
  generateAuthVerificationToken,
  unsanitizeObject,
  getUserDetailsWithAdminData, // user details with admin data
  getUsersDetailsWithAdminData // users details with admin data
  thirdPartyLogin, // same as thirdPartyLoginMiddleware. Key difference is that you can call inside your request callback.
} = authInstance.helpers();

const PORT = 3500;

app.use(express.json({ limit: "200mb" }));
app.use(cookieParser());

// It is required to read user Ip address.
app.set("trust proxy", true);

//-----------------Note for User object-----------------------------
//If you want to store some data in "privateData" or "metadata,"that should not be sent to the user or the current user, place that data in the adminOnly field. For example, use metadata = { adminOnly: { secret: "123" } } or privateData = { adminOnly: { secret: "123" } }. This way, the user or the current user will not have access to metadata.adminOnly.secret or privateData.adminOnly.secret, as this data will be ignored in req.user. If you need to access this data outside of middleware, use req.adminUser.
//------------Middleware Requirements --------------------------------

// 1) signupMiddleware - Request Body must have the following parameters 
// req.body={email:string,password:string,metadata?:object,publicData?:object,privateData?:object}
// If "disablePasswordValidation=true" then password is not requried instead secndAuthKeyName OR otp value can be provided.

// 2) loginMiddleware - Request Body must have the following parameters 
// req.body={email:string,password:string}
// If "disablePasswordValidation=true" then password is not requried instead secndAuthKeyName OR otp  value can be provided and a custom validation function required to verify user.

// 3) thirdPartyLoginMiddleware - Request Body OR Request User must have the following parameters 
// req.body={email:string,password:string,thirdPartyProvider:string,verified:boolean,metadata?:object,publicData?:object,privateData?:object} OR req.user={email:string,password:string,thirdPartyProvider:string,verified:boolean,metadata?:object,publicData?:object,privateData?:object}
// If third party provider required password and "isPasswordRequired=true" then only password is requried else remove password key from object.

// 4) newIpAddrCheckMiddleware - Request Body must have the following parameters 
// req.body={token:string}
// If "newIpAddrTokenName" is manually set then that key name must be provided.

// 5) changeAuthenticationValueMiddleware - Request body must have the following parameters 
// req.body={oldAuth:string,newAuth:string,password:string}
// If "disablePasswordValidation=true" then password is not requried instead secndAuthKeyName OR otp  value can be provided and a custom validation function required to verify user.

// 6) changePasswordMiddleware - Request body must have the following parameters 
// req.body={oldPassword:string,newPassword:string,auth:string}

// 7) resetPasswordMiddleware - Request body must have the following parameters 
// req.body={auth:string}

// 8) resetPasswordVerifyMiddleware - Request body must have the following parameters 
// req.body={token:string,newPassword:string,auth:string}

// 9) generateTokenForAuthVerificationMiddleware - Request body must have the following parameters 
// req.body={auth:string}

// 10) validateTokenForAuthVerificationMiddleware - Request body must have the following parameters 
// req.body={auth:string,token:string}

// 11) logoutMiddleware - No Request Body is required. But Authenticated user is required.

// 12) newCsrfTokenMiddleware - No Request Body is required. But Authenticated user is required.

// 13) verifyUserTokenMiddleware -No Request Body is required. But Authenticated user is required.

// 14) getCurrentUserMiddleware - No Request Body is required. But Authenticated user is required.

// 15) deleteCurrentUserMiddleware - No Request Body is required. But Authenticated user is required.

app.post("/signup", signupMiddleware(), async (req, res) => {
  try {
    //attach user details and csrf token in request object
    console.log(req.user, req.adminUser);
    const user = req.user;
    const tokenResp = await generateAuthVerificationToken({
      id: user.id,
      expiresIn: "48h",
    });
    console.log(tokenResp);
    res.sendStatus(200);
  } catch (e) {
    console.error(e);
  }
});

app.post("/login", loginMiddleware(), (req, res) => {
  try {
    //attach user details and csrf token in request object
    console.log(req.user, req.adminUser, req.csrfToken);
    res.sendStatus(200);
  } catch (e) {
    console.error(e);
  }
});

app.post("/new-ip-addr", newIpAddrCheckMiddleware(), (req, res) => {
  res.sendStatus(200);
});

app.post("/new-csrf-token", newCsrfTokenMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  console.log(req.user, req.adminUser, req.csrfToken);
  res.status(200).send({ csrfToken: req.csrfToken });
});

app.get("/logout", logoutMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  console.log(req.user, req.adminUser);
  res.sendStatus(200);
});

app.post("/userDetails", verifyUserTokenMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  console.log(req.user, req.csrfToken);
  res.sendStatus(200);
});

app.get("/current-user", getCurrentUserMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  // console.log(req.user, req.csrfToken);
  res.status(200).send(req.user);
});

app.delete(
  "/delete-current-user",
  deleteCurrentUserMiddleware(),
  (req, res) => {
    //attach user details and csrf token in request object
    console.log(req.user, req.adminUser, req.csrfToken);
    res.sendStatus(200);
  }
);

app.post("/change-email", changeAuthenticationValueMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  console.log(req.user, req.csrfToken);
  res.sendStatus(200);
});

app.post("/change-pwd", changePasswordMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  console.log(req.user, req.adminUser, req.csrfToken);
  console.log(req.user);
  res.sendStatus(200);
});

app.post("/reset-pwd", resetPasswordMiddleware(), (req, res) => {
  //attach user details ,validation token and token expire time in request object
  console.log(req.validationToken, req.user, req.adminUser, req.tokenExpiresIn);
  res.sendStatus(200);
});

app.post("/reset-pwd-verify", resetPasswordVerifyMiddleware(), (req, res) => {
  //attach user details and csrf token in request object
  console.log(req.user, req.adminUser, req.csrfToken);
  res.sendStatus(200);
});

app.post(
  "/auth-verify-gen",
  generateTokenForAuthVerificationMiddleware(),
  (req, res) => {
    //attach user details ,validation token and token expire time in request object
    console.log(
      req.validationToken,
      req.user,
      req.adminUser,
      req.tokenExpiresIn
    );
    res.sendStatus(200);
  }
);

app.post(
  "/auth-verify",
  validateTokenForAuthVerificationMiddleware(),
  (req, res) => {
    //attach user details and csrf token in request object
    console.log(req.user, req.adminUser, req.csrfToken);
    res.sendStatus(200);
  }
);

app.get("/user-details", async (req, res) => {
  const query = req.query;
  const user = await getUserDetails({ query });
  res.status(200).send(user);
});

app.get("/users-details", async (req, res) => {
  const query = req.query;
  const users = await getUsersDetails(query);
  removeKeysFromUserDetails(users);
  res.status(200).send(users);
});

app.post("/update-user-metadata", async (req, res) => {
  const { auth } = req.query;
  const { country } = req.body;
  const user = await updateUserDetails({ auth }, { metadata: { ...req.body } });
  console.log(user);
  res.sendStatus(200);
});

app.get("/google-login", googleAuthenticate);
app.get(
  "/google-login/callback",
  googleAuthenticateCallback,
  thirdPartyLoginMiddleware({ redirectpath: "/current-user" })
);

app.listen(PORT, () => {
  console.log(`listening on port ${PORT}`);
});

```


### Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request.