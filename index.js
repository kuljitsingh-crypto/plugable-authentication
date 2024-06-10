const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { EventEmitter } = require("events");
const { isEmpty, includes } = require("lodash");
const CryptoJS = require("crypto-js");
const validator = require("validator");

const USERS_PAGE_LIMIT = 100;
const EMAIL_AUTH_KEY = "email";
const OTP_AUTH_KEY = "otp";
const NEW_IP_ADDR_TOKEN_NAME = "token";
const PASSWORD_VALIDATION_PATTERN = "^[a-zA-Z0-9@$!%*?&^#~_+-]{8,256}$";
const PASSEORD_VALIDATION_NAME = '"Must be between 8 and 256 characters"';
const AUTH_KEY_VALIDATION_NAME = '"Must be valid characters"';
const MODEL_READY_EVENT = "model_ready";
const PASSWORD_HASH_SALT_LENGTH = 14;
const JWT_OPTIONS = {
  algorithm: "HS256",
  noTimestamp: false,
  expiresIn: "1h",
  notBefore: "0s",
};
const TOKEN_TYPE = "refresh_token";
const COOKIE_PREFIX = "pa-";
const COOKIE_EXPIRES_TIME = 7 * 24 * 60 * 60 * 1000;
const EXTRA_USER_PAYLOAD_FOR_TOKEN = { scope: "user" };
const JWT_ERROR = new Set(["TokenExpiredError", "NotBeforeError"]);
const TOTAL_JWT_ERROR = new Set([
  "TokenExpiredError",
  "NotBeforeError",
  "JsonWebTokenError",
]);
const JWT_EXPIRES_IN_TIME = "1d";
const CSRF_EXPIRES_IN_TIME = "1d";
const REFRESH_EXPIRES_IN_TIME = "7d";
const RESET_PWD_EXPIRES_IN_TIME = "2h";
const USER_SIGNUP_FAIL_DEFAULT_MESSAGE = "User signup failed. Try again later.";
const USER_LOGIN_FAIL_DEFAULT_MESSAGE = "User login failed. Try again later.";
const USER_IP_ADDR_ADD_FAIL_DEFAULT_MESSAGE =
  "IP address add failed. Try again later.";
const USER_LOG_OUT_FAIL_DEFAULT_MESSAGE = "Log out failed. Try again later.";
const USER_TOKEN_VERIFICATION_FAIL_DEFAULT_MESSAGE =
  "Sestion verification failed. Try again later.";
const INVALID_TOKEN_DETAILS =
  "Cookie is either invalid or does not exist. Please check and try again.";
const NEW_IP_ADDR_FOUND =
  "Looks like you tried to connect with a different IP Address.";
const NEW_IP_ADDR_DURING_LOG_OUT =
  "Looks like you tried to log out with a IP different Address.";
const NEED_AUTHENTICATION_BEFORE_USE =
  "You must be logged in before using this.";
const INVALID_CSRF_TOKEN = "Your CSRF token is invalid.";
const NEW_CSRF_TOKEN_CREATION_FAIL =
  "New CSRF token creation failed. Try again later.";
const SESSION_EXPIRE_MESSAGE =
  "Your session has expired. Please log in and try again.";

const NO_NEW_IP_ADDRESS = "Cannot add new IP address. Invalid value.";
const RESET_PWD_TOKEN_GENERATION_FAIL =
  "Reset password token generation failed. Try again later.";
const VERIFY_AUTH_TOKEN_GENERATION_FAIL =
  "Auth verification token generation failed. Try again later.";
const RESET_PWD_TOKEN_VERIFICATION_FAIL =
  "Reset password token verification failed. Try again later.";
const VERIFY_AUTH_TOKEN_VERIFICATION_FAIL =
  "Auth token verification failed. Try again later.";
const CHANGE_PWD_FAIL_MESSAGE = "Password change failed. Try again later.";
const CHANGE_AUTH_FAIL_MESSAGE =
  "Authentication details change failed. Try again later.";

const tokenValidationType = {
  ipCheck: "ipCheck",
  resetPwd: "resetPwd",
  authCheck: "authCheck",
};

const tokenValidationValues = Object.values(tokenValidationType);
const tokenValidationValuesSet = new Set(tokenValidationValues);

//===================== Model Schema ==========================//
const createSchemaForCollection = (
  authKeyName,
  disablePasswordValidation = false
) => {
  const UserSourceSchema = new mongoose.Schema(
    {
      browser: { type: String, required: true },
      ipAddr: { type: String, required: true },
      userId: { type: String, required: true },
    },
    { timestamps: true }
  );
  const AuthSchema = new mongoose.Schema(
    {
      [authKeyName]: { type: String, required: true },
      id: { type: String, required: true, default: uuidv4 },
      refreshToken: { type: String, required: true },
      csrfToken: { type: String, required: true },
      isVerified: { type: Boolean, required: true, default: false },
      metadata: { type: Object, default: {} },
      publicData: { type: Object, default: {} },
      privateData: { type: Object, default: {} },
      ...(disablePasswordValidation ? {} : { password: { type: String } }),
    },
    { timestamps: true }
  );

  const validationTokenSchema = new mongoose.Schema(
    {
      longToken: { type: String, required: true },
      userId: { type: String, required: true },
      type: { type: String, required: true, enum: tokenValidationValues },
      expiresIn: { type: Date },
    },
    { timestamps: true }
  );
  return {
    authSchema: AuthSchema,
    userSourceSchema: UserSourceSchema,
    validationTokenSchema: validationTokenSchema,
  };
};

//================ Data validation Schema===========================//
const createSchemaForDataObject = (
  authKeyName,
  secndAuthKeyName,
  disableEmailValidation,
  disablePasswordValidation,
  authKeyValidationPattern,
  passwordValidationPattern = PASSWORD_VALIDATION_PATTERN,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME,
  passwordValidationName = PASSEORD_VALIDATION_NAME
) => {
  const corrctPwdValidationPattern =
    typeof passwordValidationPattern === "string" && passwordValidationPattern
      ? passwordValidationPattern
      : PASSWORD_VALIDATION_PATTERN;

  const schema = Joi.object({
    [authKeyName]: disableEmailValidation
      ? authKeyValidationPattern &&
        authKeyValidationName &&
        typeof authKeyValidationPattern === "string" &&
        typeof authKeyValidationName === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
    ...(disablePasswordValidation
      ? secndAuthKeyName && typeof secndAuthKeyName === "string"
        ? { [secndAuthKeyName]: Joi.string() }
        : { otp: Joi.string() }
      : {
          password: Joi.string()
            .required()
            .pattern(new RegExp(corrctPwdValidationPattern), {
              name: passwordValidationName,
            }),
        }),
    metadata: Joi.object(),
    publicData: Joi.object(),
    privateData: Joi.object(),
  });
  return schema;
};

const createSchemaForChangeAuthDataObject = (
  secndAuthKeyName,
  disableEmailValidation,
  disablePasswordValidation,
  authKeyValidationPattern,
  passwordValidationPattern = PASSWORD_VALIDATION_PATTERN,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME,
  passwordValidationName = PASSEORD_VALIDATION_NAME
) => {
  const corrctPwdValidationPattern =
    typeof passwordValidationPattern === "string" && passwordValidationPattern
      ? passwordValidationPattern
      : PASSWORD_VALIDATION_PATTERN;

  const schema = Joi.object({
    oldAuth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().email().required(),
    newAuth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
    ...(disablePasswordValidation
      ? secndAuthKeyName && typeof secndAuthKeyName === "string"
        ? { [secndAuthKeyName]: Joi.string() }
        : { otp: Joi.string() }
      : {
          password: Joi.string()
            .required()
            .pattern(new RegExp(corrctPwdValidationPattern), {
              name: passwordValidationName,
            }),
        }),
  });
  return schema;
};

const createSchemaForChangePwdDataObject = (
  disableEmailValidation,
  authKeyValidationPattern,
  passwordValidationPattern = PASSWORD_VALIDATION_PATTERN,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME,
  passwordValidationName = PASSEORD_VALIDATION_NAME
) => {
  const corrctPwdValidationPattern =
    typeof passwordValidationPattern === "string" && passwordValidationPattern
      ? passwordValidationPattern
      : PASSWORD_VALIDATION_PATTERN;

  const schema = Joi.object({
    auth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
    oldPassword: Joi.string()
      .required()
      .pattern(new RegExp(corrctPwdValidationPattern), {
        name: passwordValidationName,
      }),
    newPassword: Joi.string()
      .required()
      .pattern(new RegExp(corrctPwdValidationPattern), {
        name: passwordValidationName,
      }),
  });
  return schema;
};

const createSchemaForResetPwdDataObject = (
  disableEmailValidation,
  authKeyValidationPattern,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME
) => {
  const schema = Joi.object({
    auth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
  });
  return schema;
};

const createSchemaForResetPwdVerifyDataObject = (
  disableEmailValidation,
  authKeyValidationPattern,
  passwordValidationPattern = PASSWORD_VALIDATION_PATTERN,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME,
  passwordValidationName = PASSEORD_VALIDATION_NAME
) => {
  const corrctPwdValidationPattern =
    typeof passwordValidationPattern === "string" && passwordValidationPattern
      ? passwordValidationPattern
      : PASSWORD_VALIDATION_PATTERN;
  const schema = Joi.object({
    auth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
    token: Joi.string().required(),
    newPassword: Joi.string()
      .required()
      .pattern(new RegExp(corrctPwdValidationPattern), {
        name: passwordValidationName,
      }),
  });
  return schema;
};

const createSchemaForVerifyAuthGenDataObject = (
  disableEmailValidation,
  authKeyValidationPattern,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME
) => {
  const schema = Joi.object({
    auth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
  });
  return schema;
};

const createSchemaForVerifyAuthVerDataObject = (
  disableEmailValidation,
  authKeyValidationPattern,
  authKeyValidationName = AUTH_KEY_VALIDATION_NAME
) => {
  const schema = Joi.object({
    auth: disableEmailValidation
      ? authKeyValidationPattern && typeof authKeyValidationPattern === "string"
        ? Joi.string()
            .required()
            .pattern(new RegExp(authKeyValidationPattern), {
              name: authKeyValidationName,
            })
        : Joi.string().required()
      : Joi.string().required().email(),
    token: Joi.string().required(),
  });
  return schema;
};

const createSchemaForThirdPartyLoginWithoutPwd = () => {
  const schema = Joi.object({
    email: Joi.string().required().email(),
    thirdPartyProvider: Joi.string().required(),
    verified: Joi.boolean().required(),
    metadata: Joi.object(),
    publicData: Joi.object(),
    privateData: Joi.object(),
  });
  return schema;
};

const createSchemaForThirdPartyLoginWithPwd = (
  passwordValidationPattern = PASSWORD_VALIDATION_PATTERN,
  passwordValidationName = PASSEORD_VALIDATION_NAME
) => {
  const corrctPwdValidationPattern =
    typeof passwordValidationPattern === "string" && passwordValidationPattern
      ? passwordValidationPattern
      : PASSWORD_VALIDATION_PATTERN;
  const schema = Joi.object({
    email: Joi.string().required().email(),
    thirdPartyProvider: Joi.string().required(),
    password: Joi.string()
      .required()
      .pattern(new RegExp(corrctPwdValidationPattern), {
        name: passwordValidationName,
      }),
    verified: Joi.boolean().required(),
    metadata: Joi.object(),
    publicData: Joi.object(),
    privateData: Joi.object(),
  });
  return schema;
};
//================ Encrypt/Decrypr and Hashing ========================//

const encodeToBase64 = (normalText) =>
  Buffer.from(normalText).toString("base64");

const decodeFrmBase64 = (base64Text) =>
  Buffer.from(base64Text, "base64").toString("utf8");

const encryptString = (plainText, secret) => {
  const ciphertext = CryptoJS.AES.encrypt(plainText, secret).toString();
  const base64Text = encodeToBase64(ciphertext);
  return base64Text;
};

const decryptString = (base64EncodedText, secret) => {
  const encryptedText = decodeFrmBase64(base64EncodedText);
  const plainText = CryptoJS.AES.decrypt(encryptedText, secret).toString(
    CryptoJS.enc.Utf8
  );
  return plainText;
};

const createHashPasswword = (
  password,
  saltLength = PASSWORD_HASH_SALT_LENGTH
) => {
  return new Promise((resolve, reject) => {
    bcrypt.genSalt(saltLength, function (err, salt) {
      if (err) {
        reject(err);
      }
      bcrypt.hash(password, salt, function (err, hash) {
        if (err) {
          reject(err);
        }
        resolve(encodeToBase64(hash));
      });
    });
  });
};

const isUserPasswordSame = (plainPwd, base64HashPwd) => {
  const hashPwd = decodeFrmBase64(base64HashPwd);
  return new Promise((resolve, reject) => {
    bcrypt.compare(plainPwd, hashPwd, function (err, res) {
      if (err) {
        reject(err);
        return;
      }
      resolve(res);
    });
  });
};

//====================== JWT Token============================//
const createJwtToken = (payload, secret, jwtOptions) => {
  return new Promise((resolve, reject) => {
    jwt.sign(payload, secret, jwtOptions, (err, token) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(token);
    });
  });
};

const decodeJwtToken = (jwtToken, secret) => {
  return new Promise((resolve, reject) => {
    jwt.verify(jwtToken, secret, function (err, decoded) {
      if (err) {
        reject(err);
        return;
      }
      resolve(decoded);
    });
  });
};

const decodeJwtTokenWithoutValidation = (token) => {
  return jwt.decode(token);
};

const createJWTAccessAndRefreshToken = async (
  payload,
  secret,
  encryptSecret,
  jwtOptions = {}
) => {
  if (!payload) {
    throw new Error("payload must be provided");
  }
  if (!secret) {
    throw new Error("JWT secret must be provided");
  }
  if (!encryptSecret) {
    throw new Error("Encryption secret must be provided");
  }
  const jwtOptionGivenMaybe = isValidObject(jwtOptions) ? jwtOptions : {};
  const accessTokenJwtOptions = Object.assign(
    { keyid: Date.now().toString() },
    JWT_OPTIONS,
    jwtOptionGivenMaybe
  );

  const refreshTokenJwtOptions = Object.assign(
    { keyid: Date.now().toString() },
    JWT_OPTIONS,
    jwtOptionGivenMaybe,
    { expiresIn: REFRESH_EXPIRES_IN_TIME }
  );

  const [accessToken, refreshToken] = await Promise.all([
    createJwtToken(payload, secret, accessTokenJwtOptions),
    createJwtToken(payload, secret, refreshTokenJwtOptions),
  ]);
  const decodedValue = decodeJwtTokenWithoutValidation(accessToken);
  const expiresIn = decodedValue.exp - decodedValue.iat;
  return {
    refreshToken: encryptString(refreshToken, encryptSecret),
    accessToken,
    expiresIn,
    tokenType: TOKEN_TYPE,
  };
};

const createAccessFrmRefreshToken = async (
  encodedRefreshToken,
  secret,
  encryptSecret,
  jwtOptions
) => {
  const userPayload = { ...EXTRA_USER_PAYLOAD_FOR_TOKEN };
  try {
    const jwtRefreshToken = decryptString(encodedRefreshToken, encryptSecret);
    const decodedRefreshToken =
      decodeJwtTokenWithoutValidation(jwtRefreshToken);
    userPayload.id = decodedRefreshToken.id;
    await decodeJwtToken(jwtRefreshToken, secret);
    const jwtOptionGivenMaybe = isValidObject(jwtOptions) ? jwtOptions : {};
    const accessTokenJwtOptions = Object.assign(
      { keyid: Date.now().toString() },
      JWT_OPTIONS,
      jwtOptionGivenMaybe
    );
    const accessToken = await createJwtToken(
      userPayload,
      secret,
      accessTokenJwtOptions
    );
    const decodedValue = decodeJwtTokenWithoutValidation(accessToken);
    const expiresIn = decodedValue.exp - decodedValue.iat;
    return {
      refreshToken: encodedRefreshToken,
      accessToken,
      expiresIn,
      tokenType: TOKEN_TYPE,
    };
  } catch (err) {
    if (err && err.name && JWT_ERROR.has(err.name)) {
      return createJWTAccessAndRefreshToken(
        userPayload,
        secret,
        encryptSecret,
        jwtOptions
      );
    }
    throw err;
  }
};

const createRefreshToken = async (
  payload,
  secret,
  encryptSecret,
  jwtOptions = {}
) => {
  if (!payload) {
    throw new Error("payload must be provided");
  }
  if (!secret) {
    throw new Error("JWT secret must be provided");
  }
  if (!encryptSecret) {
    throw new Error("Encryption secret must be provided");
  }

  const jwtOptionGivenMaybe = isValidObject(jwtOptions) ? jwtOptions : {};
  const refreshTokenJwtOptions = Object.assign(
    { keyid: Date.now().toString() },
    JWT_OPTIONS,
    jwtOptionGivenMaybe,
    { expiresIn: REFRESH_EXPIRES_IN_TIME }
  );

  const refreshToken = await createJwtToken(
    payload,
    secret,
    refreshTokenJwtOptions
  );

  return encryptString(refreshToken, encryptSecret);
};

//=========================== CSRF Token===========================//
const createCsrfToken = async (
  userId,
  encryptSecret,
  expiresIn = CSRF_EXPIRES_IN_TIME
) => {
  const payload = { id: userId };
  const jwtToken = await createJwtToken(payload, encryptSecret, {
    expiresIn: expiresIn || CSRF_EXPIRES_IN_TIME,
  });
  return encryptString(jwtToken, encryptSecret);
};

const isValidCsrfToken = async (
  encodeToken,
  refEncodedToken,
  encryptSecret
) => {
  let token = null,
    refToken = null;
  try {
    if (!encodeToken || !refEncodedToken || !encryptSecret) {
      return { status: false };
    }
    if (encodeToken !== refEncodedToken) {
      return { status: false };
    }
    token = decryptString(encodeToken, encryptSecret);
    refToken = decryptString(refEncodedToken, encryptSecret);

    const [decodedJwtDetails, decodedRefJwtDetails] = await Promise.all([
      decodeJwtToken(token, encryptSecret),
      decodeJwtToken(refToken, encryptSecret),
    ]);

    return { status: decodedJwtDetails.id === decodedRefJwtDetails.id };
  } catch (e) {
    if (token && refToken && e && e.name && JWT_ERROR.has(e.name)) {
      const decodedToken = decodeJwtTokenWithoutValidation(token);
      const decodedRefToken = decodeJwtTokenWithoutValidation(refToken);

      if (decodedToken && decodedRefToken) {
        const isSameId = decodedToken.id === decodedRefToken.id;

        return isSameId
          ? {
              status: isSameId,
              isExpired: true,
            }
          : { status: false };
      }
    }
    return { status: false };
  }
};

//========================== Other Helpers=======================//
const isValidObject = (obj) =>
  obj !== null &&
  obj !== undefined &&
  typeof obj === "object" &&
  obj.constructor === Object &&
  !isEmpty(obj);

const getReqUserSource = (req) => {
  const ip =
    req.ip ||
    req.headers["cf-connecting-ip"] ||
    req.headers["x-real-ip"] ||
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    "";
  const browser = req.headers["user-agent"];

  return { ipAddr: ip, browser };
};

const getCookieName = (cookieId) => `${COOKIE_PREFIX}${cookieId}`;

const resetUserCookies = (res, cookieId) => {
  res.clearCookie(getCookieName(cookieId));
};

const setUserCookies = (cookieDetails, expiresIn, cookieId, res) => {
  if (
    cookieDetails &&
    cookieDetails.refreshToken &&
    cookieDetails.accessToken &&
    res &&
    typeof res.cookie === "function" &&
    cookieId
  ) {
    const cookieName = getCookieName(cookieId);
    const cookieDetailStr = JSON.stringify(cookieDetails);
    const encryptCookieDetails = encryptString(cookieDetailStr, cookieName);
    res.cookie(cookieName, encryptCookieDetails, {
      expire: expiresIn,
      secure: true,
      httpOnly: true,
      sameSite: "lax",
    });
  }
};

const getUserCookies = (req, cookieId) => {
  try {
    const cookieName = getCookieName(cookieId);
    const cookieDetails = req.cookies || {};
    const systemCookie = cookieDetails[cookieName];
    const rawSystemCookie = decryptString(systemCookie, cookieName);
    return JSON.parse(rawSystemCookie);
  } catch (err) {
    return {};
  }
};

const getUserDetailsFrmMongo = (
  mongoUserDetails,
  includePrivateData = true
) => {
  const { _id, __v, privateData, ...requiredDetails } = mongoUserDetails;
  const finalDetails = includePrivateData
    ? { ...requiredDetails, privateData }
    : { ...requiredDetails };
  return finalDetails;
};
const removeUnnecessayUserDetails = (
  mongoUserDetails,
  includeAdminOnlyData = false,
  includePrivateData = true
) => {
  const {
    _id,
    __v,
    privateData,
    csrfToken,
    refreshToken,
    password,
    metadata,
    ...requiredDetails
  } = mongoUserDetails;
  if (includeAdminOnlyData) {
    return { ...requiredDetails, metadata, privateData };
  }
  const { adminOnly: metaAdmin, ...restMetadata } = metadata;
  const { adminOnly: privateAdmin, ...restPrivatedata } = privateData;
  const finalDetails = includePrivateData
    ? { ...requiredDetails, privateData: restPrivatedata }
    : { ...requiredDetails };
  finalDetails.metadata = restMetadata;
  return finalDetails;
};

const getReqUserCsrfToken = (req) =>
  req.headers["X-CSRF-Token"] || req.headers["x-csrf-token"];

//Middlwares
//1) Signup - done - testing done
//2) Login - done - testing done
//3) Reset Password - done - testing done
//4) Change Password - done - testing done
//5) change Auth Key - done - testing done
//6) verify token - done - testing done
//7) validate token for Auth verification - done - testing done
//8) logout - done - testing done
//9) new Ip verify - done - testing done
//10) new csrf token - done - testing done
//11) generate token for auth verification - done - testing done
//12) Reset Password token validator - done - testing done
//13) get current user details - done - testing done
//14) delete curren user - done - testing done
//15) Third party Login - done - testing done

class PlugableAuthentication {
  static #instanceObj = {};
  #mongoURI = null;
  #collectionName = null;
  #mongoConnection = null;
  #authKeyName = EMAIL_AUTH_KEY;
  #secndAuthKeyName = OTP_AUTH_KEY;
  #newIpAddrTokenName = NEW_IP_ADDR_TOKEN_NAME;
  #disableEmailValidation = false;
  #disablePasswordValidation = false;
  #disableCSRFTokenValidation = false;
  #disableIpMismatchValidation = false;
  #model = null;
  #userSourceModel = null;
  #validationTokenModel = null;
  #dataValidationSchema = null;
  #changeAuthValidationSchema = null;
  #changePwdValidationSchema = null;
  #resetPwdValidationSchema = null;
  #resetPwdVerifyValidationSchema = null;
  #verifyAuthGenValidationSchema = null;
  #verifyAuthVerValidationSchema = null;
  #authKeyValidationPattern = null;
  #authKeyValidationName = AUTH_KEY_VALIDATION_NAME;
  #passwordValidationPattern = PASSWORD_VALIDATION_PATTERN;
  #passwordValidationName = PASSEORD_VALIDATION_NAME;
  #isModelReady = false;
  #modelReadyEventEmitter = null;
  #jwtSecret = null;
  #jwtOptions = null;
  #encryptSecret = null;
  #cookieId = null;
  #jwtOptnFrIpValidation = null;
  #csrfTokenExpireTime = null;
  #tokenSenderFrIpValidationCb = null;
  #verifyAuthKeyOnCreation = false;
  #sanitizeObjectBeforeAdd = true;
  #thirdPartyLoginOption = {};

  /**
   * @param {object} options
   * @param {string} options.uri
   * @param {string} options.collection
   * @param {string} options.jwtSecret
   * @param {string} options.encryptSecret
   * @param {string} options.cookieId - 'Id to generate unique cookie name. Must be same for entire app'
   * @param {string} [options.authKeyName] - default 'email'. It will use as schema name for Db. Package will also search this key name in req.body during login and signup
   * @param {string} [options.secndAuthKeyName] - default 'otp'. It will use when disablePasswordValidation = true. Package will search this key name in req.body during login and signup
   * @param {string} [options.newIpAddrTokenName] - default 'token'. It will use get the token value for new IP address.
   * @param {boolean} [options.disablePasswordValidation]- default 'false'
   * @param {boolean} [options.disableEmailValidation]- default 'false'
   * @param {boolean} [options.disableCSRFTokenValidation] - default 'false'
   * @param {boolean} [options.disableIpMismatchValidation] - default 'false
   * @param {string} [options.authKeyValidationPattern] -default null
   * @param {string} [options.authKeyValidationName] -default '"Must be valid characters"'
   * @param {string} [options.passwordValidationPattern] - default '^[a-zA-Z0-9@$!%*?&^#~_+-]{8,256}$'
   * @param {string} [options.passwordValidationName] - default '"Must be between 8 and 256 characters"'
   * @param {object} [options.jwtOptions]- default '{algorithm: 'HS256',noTimestamp: false,expiresIn: '1h',notBefore: '0s'}'
   * @param {{expiresIn: string}} [options.jwtOptnFrIpValidation] - default null Ex: {expiresIn: "10h"/"7d"}
   * @param {(shortToken:string,tokenExpiresIn:Date | null,user:{email: string,
   * id:string,
   * createdAt:Date,
   * updatedAt:Date,
   * metadata?:object,
   * publicData?:object,
   * privateData?:object,browser:string,ipAddr:string})=>Promise<void>} [options.sendTokenForIpValidation] - defualt null
   * @param {string} [options.csrfTokenExpireTime] - default null Ex:"10h"/"7d"
   * @param {boolean} [options.verifyAuthKeyOnCreation] - default false.
   * If you want to mark your authentication key as verified on creation. set as true.
   * @param {boolean} [options.sanitizeObjectBeforeAdd] - default true.
   * sanitize metadata,privateData and publicData before adding to the database.
   * @param {{[providerName:string]:
   * {isPasswordRequired?:boolean,
   * passwordValidationPattern?:string,
   * passwordValidationName?:string}}} [options.thirdPartyLoginOption] - default empty object.
   * `providerName` representing the name of third-party authentication providers (e.g., "google", "facebook",etc.),
   * `isPasswordRequired` (default false): Indicates whether a password is required for the corresponding authentication provider,
   * `passwordValidationPattern` (default '^[a-zA-Z0-9@$!%*?&^#~_+-]{8,256}$'): Regex for validating passwords for the corresponding authentication provider,used only when `isPasswordRequired=true`,
   * `passwordValidationName` (default '"Must be valid characters"'): Message displayed when a password not match `passwordValidationPattern`, used only when `isPasswordRequired=true`.
   *
   */
  constructor(options) {
    const { collection } = options;
    if (!collection || typeof collection !== "string") {
      throw new Error("Mongo Collection name is required");
    }
    if (PlugableAuthentication.#instanceObj.hasOwnProperty(collection)) {
      return PlugableAuthentication.#instanceObj[collection];
    }
    PlugableAuthentication.#instanceObj[collection] = this;
    this.#initalizeInstance(options);
    return PlugableAuthentication.#instanceObj[collection];
  }

  #initalizeInstance(options) {
    const {
      uri,
      collection,
      authKeyName,
      secndAuthKeyName,
      disableEmailValidation,
      disablePasswordValidation,
      authKeyValidationPattern,
      passwordValidationPattern,
      disableCSRFTokenValidation,
      passwordValidationName,
      authKeyValidationName,
      jwtSecret,
      jwtOptions,
      encryptSecret,
      cookieId,
      disableIpMismatchValidation,
      newIpAddrTokenName,
      jwtOptnFrIpValidation,
      sendTokenForIpValidation,
      csrfTokenExpireTime,
      verifyAuthKeyOnCreation,
      sanitizeObjectBeforeAdd,
      thirdPartyLoginOption,
    } = options || {};
    if (!uri || typeof uri !== "string") {
      throw new Error("Mongo URI is required");
    }
    if (!collection || typeof collection !== "string") {
      throw new Error("Mongo Collection name is required");
    }
    if (!jwtSecret || typeof jwtSecret !== "string") {
      throw new Error("JWT secret is required");
    }
    if (!encryptSecret || typeof encryptSecret !== "string") {
      throw new Error("Encryption secret is required");
    }
    if (!cookieId || typeof cookieId !== "string") {
      throw new Error("Cookie ID is required");
    }
    this.#mongoURI = uri;
    this.#collectionName = collection;
    this.#jwtSecret = jwtSecret;
    this.#encryptSecret = encryptSecret;
    this.#cookieId = cookieId;
    if (authKeyName && typeof authKeyName === "string") {
      this.#authKeyName = authKeyName;
    }
    if (secndAuthKeyName && typeof secndAuthKeyName === "string") {
      this.#secndAuthKeyName = secndAuthKeyName;
    }
    if (newIpAddrTokenName && typeof newIpAddrTokenName === "string") {
      this.#newIpAddrTokenName = newIpAddrTokenName;
    }
    if (disableEmailValidation && typeof disableEmailValidation === "boolean") {
      this.#disableEmailValidation = disableEmailValidation;
    }
    if (
      disablePasswordValidation &&
      typeof disablePasswordValidation === "boolean"
    ) {
      this.#disablePasswordValidation = disablePasswordValidation;
    }
    if (
      !!authKeyValidationPattern &&
      typeof authKeyValidationPattern === "string"
    ) {
      this.#authKeyValidationPattern = authKeyValidationPattern;
    }
    if (
      !!passwordValidationPattern &&
      typeof passwordValidationPattern === "string"
    ) {
      this.#passwordValidationPattern = passwordValidationPattern;
    }
    if (passwordValidationName && typeof passwordValidationName === "string") {
      this.#passwordValidationName = passwordValidationName;
    }
    if (authKeyValidationName && typeof authKeyValidationName === "string") {
      this.#authKeyValidationName = authKeyValidationName;
    }
    if (
      disableCSRFTokenValidation &&
      typeof disableCSRFTokenValidation === "boolean"
    ) {
      this.#disableCSRFTokenValidation = disableCSRFTokenValidation;
    }
    if (isValidObject(jwtOptions)) {
      this.#jwtOptions = jwtOptions;
    }
    if (
      disableIpMismatchValidation &&
      typeof disableIpMismatchValidation === "boolean"
    ) {
      this.#disableIpMismatchValidation = disableIpMismatchValidation;
    }
    if (isValidObject(jwtOptnFrIpValidation)) {
      this.#jwtOptnFrIpValidation = {
        expiresIn: jwtOptnFrIpValidation.expiresIn || JWT_EXPIRES_IN_TIME,
      };
    }
    if (typeof sendTokenForIpValidation === "function") {
      this.#tokenSenderFrIpValidationCb = sendTokenForIpValidation;
    }
    if (csrfTokenExpireTime && typeof csrfTokenExpireTime === "string") {
      this.#csrfTokenExpireTime = csrfTokenExpireTime;
    }
    if (
      verifyAuthKeyOnCreation &&
      typeof verifyAuthKeyOnCreation === "boolean"
    ) {
      this.#verifyAuthKeyOnCreation = verifyAuthKeyOnCreation;
    }
    if (
      typeof sanitizeObjectBeforeAdd === "boolean" &&
      sanitizeObjectBeforeAdd === false
    ) {
      this.#sanitizeObjectBeforeAdd = sanitizeObjectBeforeAdd;
    }
    this.#processThirdPartyLogin(thirdPartyLoginOption);
    this.#modelReadyEventEmitter = new EventEmitter();
    this.#mongoConnect(uri);
  }

  async #mongoConnect(uri) {
    try {
      if (!uri) throw new Error("No Mongo URI Found");
      const connect = await mongoose.connect(uri);
      this.#mongoConnection = connect.connection;
      const { userSourceSchema, authSchema, validationTokenSchema } =
        createSchemaForCollection(
          this.#authKeyName,
          this.#disablePasswordValidation
        );
      const userSourceCollectionName = `${this.#collectionName}_userSource`;
      const validationCollectionName = `${this.#collectionName}_user_validationToken`;
      this.#model = mongoose.model(this.#collectionName, authSchema);
      this.#userSourceModel = mongoose.model(
        userSourceCollectionName,
        userSourceSchema
      );
      this.#validationTokenModel = mongoose.model(
        validationCollectionName,
        validationTokenSchema
      );
      this.#dataValidationSchema = createSchemaForDataObject(
        this.#authKeyName,
        this.#secndAuthKeyName,
        this.#disableEmailValidation,
        this.#disablePasswordValidation,
        this.#authKeyValidationPattern,
        this.#passwordValidationPattern,
        this.#authKeyValidationName,
        this.#passwordValidationName
      );
      this.#changeAuthValidationSchema = createSchemaForChangeAuthDataObject(
        this.#secndAuthKeyName,
        this.#disableEmailValidation,
        this.#disablePasswordValidation,
        this.#authKeyValidationPattern,
        this.#passwordValidationPattern,
        this.#authKeyValidationName,
        this.#passwordValidationName
      );
      this.#changePwdValidationSchema = createSchemaForChangePwdDataObject(
        this.#disableEmailValidation,
        this.#authKeyValidationPattern,
        this.#passwordValidationPattern,
        this.#authKeyValidationName,
        this.#passwordValidationName
      );
      this.#resetPwdValidationSchema = createSchemaForResetPwdDataObject(
        this.#disableEmailValidation,
        this.#authKeyValidationPattern,
        this.#authKeyValidationName
      );
      this.#resetPwdVerifyValidationSchema =
        createSchemaForResetPwdVerifyDataObject(
          this.#disableEmailValidation,
          this.#authKeyValidationPattern,
          this.#passwordValidationPattern,
          this.#authKeyValidationName,
          this.#passwordValidationName
        );
      this.#verifyAuthGenValidationSchema =
        createSchemaForVerifyAuthGenDataObject(
          this.#disableEmailValidation,
          this.#authKeyValidationPattern,
          this.#authKeyValidationName
        );
      this.#verifyAuthVerValidationSchema =
        createSchemaForVerifyAuthVerDataObject(
          this.#disableEmailValidation,
          this.#authKeyValidationPattern,
          this.#authKeyValidationName
        );
      this.#isModelReady = true;
      this.#modelReadyEventEmitter.emit(MODEL_READY_EVENT);
      console.log(`Connected to Mongo DB URI: ${this.#mongoURI}`);
    } catch (err) {
      console.error(
        `Failed to connect to Mongo DB URI: ${this.#mongoURI}`,
        err
      );
      throw err;
    }
  }

  #processThirdPartyLogin(thirdPartyLoginOption) {
    if (
      thirdPartyLoginOption !== null &&
      typeof thirdPartyLoginOption === "object" &&
      thirdPartyLoginOption.constructor === Object
    ) {
      const entries = Object.entries(thirdPartyLoginOption);
      for (const entry of entries) {
        const [key, value] = entry;
        const {
          isPasswordRequired,
          passwordValidationPattern,
          passwordValidationName,
        } = value;
        this.#thirdPartyLoginOption[key] = {
          schema: isPasswordRequired
            ? createSchemaForThirdPartyLoginWithPwd(
                passwordValidationPattern || PASSWORD_VALIDATION_PATTERN,
                passwordValidationName || PASSEORD_VALIDATION_NAME
              )
            : createSchemaForThirdPartyLoginWithoutPwd(),
        };
      }
    }
  }

  #waitUntilModelReady() {
    return new Promise((resolve) => {
      const modelCheckCb = () => {
        if (this.#isModelReady) {
          resolve();
        } else {
          this.#modelReadyEventEmitter.on(MODEL_READY_EVENT, resolve);
        }
      };
      modelCheckCb();
    });
  }

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   * @param {((requestBody:object, user:object)=>Promise<boolean>)} [params.customValidation]
   * @param {string} [params.validationLabelName]
   *
   */
  #loginMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler, customValidation, validationLabelName } =
        params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const tokenDetails = await this.#verifyUserLogin(
          req,
          customValidation,
          validationLabelName,
          this.#jwtOptnFrIpValidation,
          this.#tokenSenderFrIpValidationCb
        );

        if (!tokenDetails) {
          const msg =
            "You're tring to login with different IP address.Please allow this, if you want to countinue.";
          this.#createAndThrowError(msg, 401);
        }
        setUserCookies(tokenDetails, COOKIE_EXPIRES_TIME, this.#cookieId, res);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_LOGIN_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   * @param {string} [params.redirectpath]
   *
   */
  #thirdPartyLoginMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler, redirectpath } = params || {};
      await this.#waitUntilModelReady();
      try {
        if (
          typeof req.user === "object" &&
          req.user !== null &&
          !Array.isArray(req.user)
        ) {
          req.body = req.user;
        }
        const requestBody = req.body;
        const { thirdPartyProvider } = requestBody;
        const isValidThirdPartyProvider =
          thirdPartyProvider &&
          typeof thirdPartyProvider === "string" &&
          this.#thirdPartyLoginOption[thirdPartyProvider] &&
          this.#thirdPartyLoginOption[thirdPartyProvider].hasOwnProperty(
            "schema"
          );
        if (!isValidThirdPartyProvider) {
          const msg = "The third party provider does not exist.";
          this.#createAndThrowError(msg, 400);
        }
        const validationSchema =
          this.#thirdPartyLoginOption[thirdPartyProvider].schema;

        const errorMessage = this.#requestDataValidationHelper(
          validationSchema,
          requestBody
        );

        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const tokenDetails = await this.#verifyThirdPartyUserLogin(req);

        if (!tokenDetails) {
          const msg =
            "You're tring to login with different IP address.Please allow this, if you want to countinue.";
          this.#createAndThrowError(msg, 401);
        }
        setUserCookies(tokenDetails, COOKIE_EXPIRES_TIME, this.#cookieId, res);
        if (redirectpath && typeof redirectpath === "string") {
          res.redirect(redirectpath);
          return;
        }
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_LOGIN_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   * @param {object} options
   * @param {((reqBody:object)=>boolean)|boolean} [options.isCurrentUserVerified]
   * @param {(err:Error,resp:object)=>void} [options.errorHandler]
   *
   */
  #signupMiddlware = (options) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler, isCurrentUserVerified } = options || {};
      try {
        const errorMessage = this.#validateRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        await this.#createUser(req, isCurrentUserVerified);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_SIGNUP_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   */
  #newIpAddrCheckMiddleware = (params) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler } = params || {};
      try {
        const requestBody = req.body || {};
        const token = requestBody[this.#newIpAddrTokenName];
        if (!token || typeof token !== "string") {
          const msg = '"token" is required.';
          this.#createAndThrowError(msg, 400);
        }
        const userPayload = await this.#errorRespWrapper(
          res,
          this.#verifyValidationToken
        )(token, NO_NEW_IP_ADDRESS, NO_NEW_IP_ADDRESS);
        const { userId, ipAddr, browser } = userPayload;
        await this.#userSourceModel
          .findOneAndUpdate(
            { userId, ipAddr, browser },
            {},
            { lean: true, upsert: true }
          )
          .exec();
        await this.#removeValidationToken(token, NO_NEW_IP_ADDRESS);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_IP_ADDR_ADD_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   */
  #logoutMiddleware = (params) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler } = params || {};
      try {
        const cookieDetail = getUserCookies(req, this.#cookieId);
        const user = await this.#verifyToken(cookieDetail, false);
        if (!user) {
          this.#createAndThrowError(NEED_AUTHENTICATION_BEFORE_USE, 401);
        }
        await this.#verifyUserIpAddrAndCsrfToken(req, {
          userId: user.id,
          csrfToken: user.csrfToken,
          newIpAddrErrMsg: NEW_IP_ADDR_DURING_LOG_OUT,
        });
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(user);
        resetUserCookies(res, this.#cookieId);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_LOG_OUT_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   */
  #newCsrfTokenMiddleware = (params) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler } = params || {};
      try {
        const { user } = await this.#validateUserAuthentication(req, {
          throwErrorOnInvalidCsrfToken: false,
          throwErrorOnAccessTokenExpire: false,
          includeUserCsrfToken: false,
        });
        const userId = user.id;
        const userNewDetails = await this.#createNewCsrfToken(userId);
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(userNewDetails);
        req.csrfToken = userNewDetails.csrfToken;
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          NEW_CSRF_TOKEN_CREATION_FAIL
        );
      }
    };
  };

  /**
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   */
  #verifyUserTokenMiddleware = (params) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler } = params || {};
      try {
        const { user, isCsrfTokenExpired } =
          await this.#validateUserAuthentication(req, {
            throwErrorOnAccessTokenExpire: false,
            createNewAccessTokenOnExpires: true,
            includeUserCsrfToken: true,
          });
        const { tokenDetails, ...restUserDetails } = user;
        const newUserDetails = await this.#checkAndCreateNewCsrfToken(
          restUserDetails,
          isCsrfTokenExpired
        );
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(newUserDetails);
        req.csrfToken = newUserDetails.csrfToken;
        setUserCookies(tokenDetails, COOKIE_EXPIRES_TIME, this.#cookieId, res);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_TOKEN_VERIFICATION_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   */
  #deleteCurrentUserMiddleware = (params) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler } = params || {};
      try {
        const { user } = await this.#validateUserAuthentication(req, {
          throwErrorOnAccessTokenExpire: false,
          createNewAccessTokenOnExpires: false,
          includeUserCsrfToken: true,
        });
        const userAuth = user[this.#authKeyName];
        const userId = user.id;
        await Promise.all([
          this.#model.findOneAndDelete({ id: userId }).exec(),
          this.#userSourceModel.deleteMany({ userId }).exec(),
          this.#validationTokenModel
            .deleteMany({
              $or: [{ userId }, { userId: userAuth }],
            })
            .exec(),
        ]);
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(user);
        req.csrfToken = null;
        resetUserCookies(res, this.#cookieId);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          USER_TOKEN_VERIFICATION_FAIL_DEFAULT_MESSAGE
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   * @param {((requestBody:object, user:object)=>Promise<boolean>)} [params.customValidation]
   * @param {string} [params.validationLabelName]
   *
   */
  #changeAuthenticationValueMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler, customValidation, validationLabelName } =
        params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateChangeAuthRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const { user, isCsrfTokenExpired } =
          await this.#validateUserAuthentication(req, {
            throwErrorOnAccessTokenExpire: false,
            createNewAccessTokenOnExpires: true,
            includeUserCsrfToken: true,
          });
        const { oldAuth, newAuth } = req.body;
        if (oldAuth === newAuth) {
          const msg =
            '"Your old and new authentication information must different."';
          this.#createAndThrowError(msg, 400);
        }
        const requestBody = {
          ...(req.body || {}),
          [this.#authKeyName]: oldAuth,
        };
        await this.#verifyUserFrstAndSecndAuthKey(
          requestBody,
          user,
          customValidation,
          validationLabelName
        );
        const userForNewAuth = await this.#getUserByQuery(
          { [this.#authKeyName]: newAuth },
          false,
          ""
        );

        if (userForNewAuth) {
          const msg = `The given ${this.#authKeyName} has already been taken. Please use different one.`;
          this.#createAndThrowError(msg, 401);
        }

        const newUserDetails = await this.#updateUserByQuery(
          { id: user.id },
          {
            [this.#authKeyName]: newAuth,
            isVerified: this.#verifyAuthKeyOnCreation,
          }
        );
        const { tokenDetails } = user;
        const restUserDetails = await this.#checkAndCreateNewCsrfToken(
          newUserDetails,
          isCsrfTokenExpired
        );
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(restUserDetails);
        req.csrfToken = restUserDetails.csrfToken;
        setUserCookies(tokenDetails, COOKIE_EXPIRES_TIME, this.#cookieId, res);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          CHANGE_AUTH_FAIL_MESSAGE
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   *
   */
  #changePasswordMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler } = params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateChangePwdRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const { user, isCsrfTokenExpired } =
          await this.#validateUserAuthentication(req, {
            throwErrorOnAccessTokenExpire: false,
            createNewAccessTokenOnExpires: true,
            includeUserCsrfToken: true,
          });
        const { newPassword, auth, oldPassword } = req.body || {};
        const requestBody = {
          ...(req.body || {}),
          [this.#authKeyName]: auth,
          password: oldPassword,
        };
        await this.#verifyUserFrstAndSecndAuthKey(requestBody, user);
        const isNewPwdIsSame = await isUserPasswordSame(
          newPassword,
          user.password
        );
        if (isNewPwdIsSame) {
          const errorMessage =
            "New password must be different from previous one.";
          this.#createAndThrowError(errorMessage, 400);
        }
        const newHashPassword = await createHashPasswword(newPassword);
        const newUserDetails = await this.#updateUserByQuery(
          { id: user.id },
          {
            password: newHashPassword,
          }
        );
        const { tokenDetails } = user;
        const restUserDetails = await this.#checkAndCreateNewCsrfToken(
          newUserDetails,
          isCsrfTokenExpired
        );
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(restUserDetails);
        req.csrfToken = restUserDetails.csrfToken;
        setUserCookies(tokenDetails, COOKIE_EXPIRES_TIME, this.#cookieId, res);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          CHANGE_PWD_FAIL_MESSAGE
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   * @param {string} [params.expiresIn] - default '2h'
   *
   */
  #resetPasswordMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler, expiresIn } = params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateResetPwdRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const { auth } = req.body || {};
        const preSavedUser = await this.#getUserByQuery(
          { [this.#authKeyName]: auth },
          true
        );
        const userPayload = {
          [this.#authKeyName]: auth,
          id: preSavedUser.id,
          tokenType: tokenValidationType.resetPwd,
          password: preSavedUser.password,
        };
        const jwtOptions = {
          expiresIn:
            expiresIn && typeof expiresIn === "string"
              ? expiresIn
              : RESET_PWD_EXPIRES_IN_TIME,
        };
        const { token: shortToken, expiresIn: tokenExpiresIn } =
          await this.#generateValidationToken(
            auth,
            tokenValidationType.resetPwd,
            userPayload,
            jwtOptions
          );
        req.validationToken = shortToken;
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(preSavedUser);
        req.tokenExpiresIn = tokenExpiresIn;
        resetUserCookies(res, this.#cookieId);
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          RESET_PWD_TOKEN_GENERATION_FAIL
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   *
   */
  #resetPasswordVerifyMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler } = params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateResetPwdVerifyRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const { auth, token, newPassword } = req.body || {};
        const userPayload = await await this.#errorRespWrapper(
          res,
          this.#verifyValidationToken
        )(
          token,
          RESET_PWD_TOKEN_VERIFICATION_FAIL,
          RESET_PWD_TOKEN_VERIFICATION_FAIL
        );
        const savedAuthValue = userPayload[this.#authKeyName];
        const prePasswords = userPayload.password;
        const userId = userPayload.id;
        const tokenType = userPayload.tokenType;
        if (
          savedAuthValue !== auth ||
          tokenType !== tokenValidationType.resetPwd
        ) {
          const msg = `User's ${this.#authKeyName} does not match with requested one. Please double check and try again.`;
          this.#createAndThrowError(msg, 400);
        }
        const isPwdSame = await isUserPasswordSame(newPassword, prePasswords);
        if (isPwdSame) {
          return res
            .status(400)
            .send("New password must be different from previous one.");
        }
        const hashPassword = await createHashPasswword(newPassword);
        const csrfToken = await createCsrfToken(
          userId,
          this.#encryptSecret,
          this.#csrfTokenExpireTime
        );
        const newUserDetails = await this.#updateUserByQuery(
          { id: userId },
          { password: hashPassword, csrfToken }
        );
        await this.#removeValidationToken(
          token,
          RESET_PWD_TOKEN_VERIFICATION_FAIL
        );
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(newUserDetails);
        req.csrfToken = newUserDetails.csrfToken;
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          RESET_PWD_TOKEN_VERIFICATION_FAIL
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   * @param {string} [params.expiresIn] - default '2h'
   *
   */
  #generateTokenForAuthVerificationMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler, expiresIn } = params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateVerifyAuthGenRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const { user: preSavedUser, isCsrfTokenExpired } =
          await this.#validateUserAuthentication(req, {
            throwErrorOnAccessTokenExpire: false,
            createNewAccessTokenOnExpires: true,
            includeUserCsrfToken: true,
          });
        if (preSavedUser.isVerified) {
          const errorMessage = `User with given ${this.#authKeyName} has already been verified.`;
          this.#createAndThrowError(errorMessage, 401);
        }
        const { auth } = req.body || {};
        if (preSavedUser[this.#authKeyName] !== auth) {
          const errorMessage = `User's ${this.#authKeyName} does not match with requested one. Please double check and try again.`;
          this.#createAndThrowError(errorMessage, 401);
        }
        const userPayload = {
          [this.#authKeyName]: auth,
          id: preSavedUser.id,
          tokenType: tokenValidationType.authCheck,
        };
        const jwtOptions = {
          expiresIn:
            expiresIn && typeof expiresIn === "string"
              ? expiresIn
              : RESET_PWD_EXPIRES_IN_TIME,
        };
        const { token: shortToken, expiresIn: tokenExpiresIn } =
          await this.#generateValidationToken(
            auth,
            tokenValidationType.authCheck,
            userPayload,
            jwtOptions
          );
        const userNewDetails = await this.#checkAndCreateNewCsrfToken(
          preSavedUser,
          isCsrfTokenExpired
        );
        req.validationToken = shortToken;
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(userNewDetails);
        req.tokenExpiresIn = tokenExpiresIn;
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          VERIFY_AUTH_TOKEN_GENERATION_FAIL
        );
      }
    };
  };

  /**
   *
   * @param {object} params
   * @param {(err:Error,resp:object)=>void} [params.errorHandler]
   *
   */
  #validateTokenForAuthVerificationMiddleware = (params) => {
    return async (req, res, next) => {
      const { errorHandler } = params || {};
      await this.#waitUntilModelReady();
      try {
        const errorMessage = this.#validateVerifyAuthVerRequestData(req.body);
        if (errorMessage) {
          this.#createAndThrowError(errorMessage, 400);
        }
        const { user: preSavedUser } = await this.#validateUserAuthentication(
          req,
          {
            throwErrorOnAccessTokenExpire: false,
            createNewAccessTokenOnExpires: true,
            includeUserCsrfToken: true,
          }
        );
        if (preSavedUser.isVerified) {
          const errorMessage = `User with given ${this.#authKeyName} has already been verified.`;
          this.#createAndThrowError(errorMessage, 400);
        }
        const { auth, token } = req.body || {};
        const userPayload = await this.#errorRespWrapper(
          res,
          this.#verifyValidationToken
        )(
          token,
          VERIFY_AUTH_TOKEN_VERIFICATION_FAIL,
          VERIFY_AUTH_TOKEN_VERIFICATION_FAIL
        );
        const preSavedUserAuthValue = preSavedUser[this.#authKeyName];
        const savedAuthValue = userPayload[this.#authKeyName];
        const tokenType = userPayload.tokenType;
        const userId = userPayload.id;
        if (
          savedAuthValue !== auth ||
          savedAuthValue !== preSavedUserAuthValue ||
          auth !== preSavedUserAuthValue ||
          tokenType !== tokenValidationType.authCheck
        ) {
          const msg = `User's ${this.#authKeyName} does not match with requested one. Please double check and try again.`;
          this.#createAndThrowError(msg, 400);
        }
        const csrfToken = await createCsrfToken(
          userId,
          this.#encryptSecret,
          this.#csrfTokenExpireTime
        );
        const newUserDetails = await this.#updateUserByQuery(
          { id: userId },
          { isVerified: true, csrfToken }
        );
        await this.#removeValidationToken(
          token,
          VERIFY_AUTH_TOKEN_VERIFICATION_FAIL
        );
        req.adminUser = removeUnnecessayUserDetails(user, true);
        req.user = removeUnnecessayUserDetails(newUserDetails);
        req.csrfToken = newUserDetails.csrfToken;
        next();
      } catch (e) {
        return this.#errorHandler(
          e,
          res,
          errorHandler,
          VERIFY_AUTH_TOKEN_VERIFICATION_FAIL
        );
      }
    };
  };

  //=============== new csrf token helper ===================//

  #checkAndCreateNewCsrfToken = async (user, isExpired) => {
    if (isExpired) {
      return this.#createNewCsrfToken(user.id);
    }
    return getUserDetailsFrmMongo(user);
  };

  #createNewCsrfToken = async (userId) => {
    const csrfToken = await createCsrfToken(
      userId,
      this.#encryptSecret,
      this.#csrfTokenExpireTime
    );
    const userNewDetails = await this.#updateUserByQuery(
      { id: userId },
      { csrfToken }
    );
    return userNewDetails;
  };

  //=============== request data validation helper================//
  #requestDataValidationHelper(joiSchema, requestBody) {
    const validationResult = joiSchema.validate(requestBody || {});
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#dataValidationSchema,
      requestBody
    );
  }

  #validateChangeAuthRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#changeAuthValidationSchema,
      requestBody
    );
  }

  #validateChangePwdRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#changePwdValidationSchema,
      requestBody
    );
  }

  #validateResetPwdRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#resetPwdValidationSchema,
      requestBody
    );
  }

  #validateResetPwdVerifyRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#resetPwdVerifyValidationSchema,
      requestBody
    );
  }

  #validateVerifyAuthGenRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#verifyAuthGenValidationSchema,
      requestBody
    );
  }

  #validateVerifyAuthVerRequestData(requestBody) {
    return this.#requestDataValidationHelper(
      this.#verifyAuthVerValidationSchema,
      requestBody
    );
  }

  //==============user helper==================//

  /**
   *
   * @param {object} details
   * @param {{auth?:string,id?:string,metadata?:object,privateData?:object,publicData?:object}} details.query
   * @returns {object|null}
   */
  #formatQuery(details) {
    const isValidDetails = isValidObject(details);
    if (!isValidDetails) return null;

    const { query } = details || {};

    const isVaildQuery = isValidObject(query);

    if (!isVaildQuery) {
      return null;
    }
    const { auth, id, metadata, publicData, privateData } = query || {};

    const correctQuery = {};
    if (typeof id === "string" && id) {
      correctQuery.id = id;
    }
    if (typeof auth === "string" && auth) {
      correctQuery[this.#authKeyName] = auth;
    }
    if (isValidObject(metadata)) {
      const entries = Object.entries(metadata);
      const metaQuery = entries.reduce((prev, curnt) => {
        const [key, val] = curnt;
        const newKeyname = `metadata.${key}`;
        prev[newKeyname] = val;
        return prev;
      }, {});
      Object.assign(correctQuery, metaQuery);
    }
    if (isValidObject(publicData)) {
      const entries = Object.entries(publicData);
      const publicQuery = entries.reduce((prev, curnt) => {
        const [key, val] = curnt;
        const newKeyname = `publicData.${key}`;
        prev[newKeyname] = val;
        return prev;
      }, {});
      Object.assign(correctQuery, publicQuery);
    }
    if (isValidObject(privateData)) {
      const entries = Object.entries(privateData);
      const privateQuery = entries.reduce((prev, curnt) => {
        const [key, val] = curnt;
        const newKeyname = `privateData.${key}`;
        prev[newKeyname] = val;
        return prev;
      }, {});
      Object.assign(correctQuery, privateQuery);
    }

    if (isEmpty(correctQuery)) {
      return null;
    }
    return correctQuery;
  }

  /**
   * @param {object} details
   * @param {{auth?:string,id?:string,metadata?:object,privateData?:object,publicData?:object}} details.query -
   * auth value is used like this email=auth,if authKeyName='email'.
   * For metadata, publicData or privateData, use like this metadata:{key:string,'a.b':number}
   * @param {boolean} [details.throwErrOnUserNotFound]
   * @param {string} [details.userNotFoundMsg]
   * @return {Promise<object|null>}
   */
  #getUserByQueryHelper = async (details) => {
    const correctQuery = this.#formatQuery(details);
    if (!correctQuery) return null;
    const { throwErrOnUserNotFound = false, userNotFoundMsg = "" } =
      details || {};
    await this.#waitUntilModelReady();
    return this.#getUserByQuery(
      correctQuery,
      throwErrOnUserNotFound,
      userNotFoundMsg,
      {
        _id: 0,
        __v: 0,
        csrfToken: 0,
        password: 0,
        refreshToken: 0,
        privateData: 0,
        "metadata.adminOnly": 0,
      }
    );
  };

  /**
   * @param {object} details
   * @param {{auth?:string,id?:string,metadata?:object,privateData?:object,publicData?:object}} details.query -
   * auth value is used like this email=auth,if authKeyName='email'.
   * For metadata, publicData or privateData, use like this metadata:{key:string,'a.b':number}
   * @param {boolean} [details.throwErrOnUserNotFound]
   * @param {string} [details.userNotFoundMsg]
   * @return {Promise<object|null>}
   */
  #getUserDetailsAdminData = async (details) => {
    const correctQuery = this.#formatQuery(details);
    if (!correctQuery) return null;
    const { throwErrOnUserNotFound = false, userNotFoundMsg = "" } =
      details || {};
    await this.#waitUntilModelReady();
    return this.#getUserByQuery(
      correctQuery,
      throwErrOnUserNotFound,
      userNotFoundMsg,
      {
        _id: 0,
        __v: 0,
        csrfToken: 0,
        password: 0,
        refreshToken: 0,
      }
    );
  };

  /**
   * @param {{auth?:string,id?:string,metadata?:object,privateData?:object,publicData?:object}} query -
   * auth value is used like this email=auth,if authKeyName='email'.
   * For metadata, publicData or privateData, use like this metadata:{key:string,'a.b':number}
   * @param {number} page
   * @param {number} perPage
   * @return {Promise<array>}
   */
  #getUsersByQueryHelper = async (
    query,
    page = 1,
    perPage = USERS_PAGE_LIMIT
  ) => {
    const correctQuery = this.#formatQuery({ query });
    if (!correctQuery) return [];
    await this.#waitUntilModelReady();
    return this.#getUsersByQuery(correctQuery, page, perPage);
  };

  /**
   * @param {{auth?:string,id?:string,metadata?:object,privateData?:object,publicData?:object}} query -
   * auth value is used like this email=auth,if authKeyName='email'.
   * For metadata, publicData or privateData, use like this metadata:{key:string,'a.b':number}
   * @param {number} page
   * @param {number} perPage
   * @return {Promise<array>}
   */
  #getUsersByQueryHelperForAdminData = async (
    query,
    page = 1,
    perPage = USERS_PAGE_LIMIT
  ) => {
    const correctQuery = this.#formatQuery({ query });
    if (!correctQuery) return [];
    await this.#waitUntilModelReady();
    return this.#getUsersByQuery(correctQuery, page, perPage, true);
  };

  /**
   * @param {object} userOption
   * @param {string} [userOption.id]
   * @param {string} [userOption.auth]
   * @param {string} [userOption.expiresIn] - Specifies the expiration of the token like '2h or 10d. For more information see jsonwebtoken.'
   */
  #generateAuthVerificationToken = async (userOption) => {
    const { id, auth, expiresIn } = userOption || {};
    if (!id && !auth)
      throw new Error("Either userOption.id or auth is required.");
    const query = {};
    let hasValidQuery = false;
    if (id && typeof id == "string") {
      query.id = id;
      hasValidQuery = true;
    } else if (auth && typeof auth === "string") {
      query[this.#authKeyName] = auth;
      hasValidQuery = true;
    }
    if (!hasValidQuery) throw new Error("Invalid userOption.");
    const user = await this.#getUserByQueryHelper({ query }, true);
    if (user.isVerified) {
      return { status: false, message: "The User has already been verified." };
    }
    const userAuth = user[this.#authKeyName];
    const userPayload = {
      [this.#authKeyName]: userAuth,
      id: user.id,
      tokenType: tokenValidationType.authCheck,
    };
    const jwtOptions = {
      expiresIn:
        expiresIn && typeof expiresIn === "string"
          ? expiresIn
          : RESET_PWD_EXPIRES_IN_TIME,
    };
    const { token: shortToken, expiresIn: tokenExpiresIn } =
      await this.#generateValidationToken(
        userAuth,
        tokenValidationType.authCheck,
        userPayload,
        jwtOptions
      );
    return { status: true, shortToken, expiresIn: tokenExpiresIn };
  };

  /**
   * @param {{auth?:string,id?:string,metadata?:object,publicData?:object,privateData?:data}} updateQuery -
   * auth value is used like this email=auth,if authKeyName='email'.
   * @param {{metadata?:object,publicData?:object,privateData?:data}} updateData
   */
  #updateUserByQueryHelper = async (updateQuery, updateData) => {
    const isValidParams =
      isValidObject(updateData) && isValidObject(updateQuery);
    if (!isValidParams) return null;
    const user = await this.#getUserByQueryHelper({
      query: updateQuery,
      throwErrOnUserNotFound: false,
    });
    if (!user) return null;
    const { metadata, publicData, privateData } = updateData;
    const extraUpdateData = {
      metadata: isValidObject(metadata)
        ? { ...user.metadata, ...this.#sanitizeObject(metadata) }
        : user.metadata,
      publicData: isValidObject(publicData)
        ? { ...user.publicData, ...this.#sanitizeObject(publicData) }
        : user.publicData,
      privateData: isValidObject(privateData)
        ? { ...user, ...this.#sanitizeObject(privateData) }
        : user.privateData,
    };

    await this.#waitUntilModelReady();
    return this.#updateUserByQuery({ id: user.id }, { $set: extraUpdateData });
  };

  #getUserByQuery = async (
    query,
    throwErrOnUserNotFound = true,
    userNotFoundMsg = "",
    removeKeys = null
  ) => {
    const correctRemoveKeys = isValidObject(removeKeys) ? removeKeys : null;
    const user = await this.#model
      .findOne(query, correctRemoveKeys, { lean: true })
      .exec();
    if (!user && throwErrOnUserNotFound) {
      const msg =
        userNotFoundMsg ||
        `User with given ${this.#authKeyName} does not exists. Please double-check and try again.`;
      this.#createAndThrowError(msg, 400);
    }
    return user ? getUserDetailsFrmMongo(user) : null;
  };

  #getUsersByQuery = async (
    query,
    page = 1,
    perPage = USERS_PAGE_LIMIT,
    includeAdminData = false
  ) => {
    const currentPage = (page - 1) * perPage;
    const adminDataMaybe = includeAdminData
      ? {}
      : { "metadata.adminOnly": 0, privateData: 0 };
    const pipline = [
      { $match: query },
      {
        $project: {
          _id: 0,
          __v: 0,
          csrfToken: 0,
          password: 0,
          refreshToken: 0,
          ...adminDataMaybe,
        },
      },
      { $skip: currentPage },
      { $limit: perPage },
    ];
    const users = await this.#model.aggregate(pipline).exec();
    return users;
  };

  #createUser = async (req, isCurrentUserVerified) => {
    const requestBody = req.body || {};
    const authKeyValue = requestBody[this.#authKeyName];
    const preSavedUser = await this.#model
      .findOne({ [this.#authKeyName]: authKeyValue })
      .exec();

    if (!!preSavedUser) {
      const msg = `User with given ${this.#authKeyName} already exists. Please log in with your registered ${this.#authKeyName}.`;
      this.#createAndThrowError(msg, 400);
    }
    const isVerified =
      this.#verifyAuthKeyOnCreation ||
      (typeof isCurrentUserVerified === "boolean"
        ? isCurrentUserVerified
        : typeof isCurrentUserVerified === "function"
          ? !!isCurrentUserVerified(requestBody)
          : false);
    requestBody.verified = isVerified;
    const userSource = getReqUserSource(req);
    const newUser = await this.#createNewUser(
      authKeyValue,
      requestBody,
      userSource
    );
    const userDetails = getUserDetailsFrmMongo(newUser, true);
    req.adminUser = removeUnnecessayUserDetails(user, true);
    req.user = removeUnnecessayUserDetails(userDetails);
  };

  async #createNewUser(
    authKeyValue,
    restBody,
    userSource,
    isThirdPartyUser = false
  ) {
    const {
      publicData,
      privateData,
      metadata,
      password,
      verified,
      thirdPartyProvider,
    } = restBody;
    const hashPassword = {};
    if (!!password) {
      hashPassword.password = await createHashPasswword(password);
    }
    const extraDataMaybe = {
      publicData: isValidObject(publicData)
        ? this.#sanitizeObject(publicData)
        : {},
      privateData: isValidObject(privateData)
        ? this.#sanitizeObject(privateData)
        : {},
      metadata: isValidObject(metadata) ? this.#sanitizeObject(metadata) : {},
    };
    if (isThirdPartyUser) {
      extraDataMaybe.privateData.isThirdPartyLogin = isThirdPartyUser;
    }
    if (thirdPartyProvider) {
      extraDataMaybe.privateData.thirdPartyProvider = thirdPartyProvider;
    }
    const userId = uuidv4();
    const userPayload = { id: userId, ...EXTRA_USER_PAYLOAD_FOR_TOKEN };
    const isVerified = !!verified;
    const [refreshToken, csrfToken] = await Promise.all([
      createRefreshToken(
        userPayload,
        this.#jwtSecret,
        this.#encryptSecret,
        this.#jwtOptions
      ),
      createCsrfToken(userId, this.#encryptSecret, this.#csrfTokenExpireTime),
    ]);

    const newUserDetails = {
      id: userId,
      [this.#authKeyName]: authKeyValue,
      csrfToken,
      refreshToken: refreshToken,
      isVerified: isVerified,
      ...extraDataMaybe,
      ...hashPassword,
    };

    const newUser = await this.#updateUserByQuery(
      { id: userId },
      newUserDetails,
      {
        upsert: true,
      }
    );
    await this.#userSourceModel
      .findOneAndUpdate({ userId, ...userSource }, {}, { upsert: true })
      .exec();
    return newUser;
  }

  #updateUserByQuery = async (updateQuery, updateData, extraOptions = {}) => {
    const userNewDetails = await this.#model
      .findOneAndUpdate(updateQuery, updateData, {
        new: true,
        lean: true,
        ...extraOptions,
      })
      .exec();
    return getUserDetailsFrmMongo(userNewDetails);
  };

  /**
   *@description It removes the specified key from the user details. Try to use less nested key in keys array
   * @param {object} user
   * @param {object} options
   * @param {string[]} options.keys -
   * By Default remove privateData,csrfToken,password,updatedAt,refreshToken.
   * Keys provided in array will append with default one.
   * @param {boolean} options.createNewCopy - Default false. Create new copy of object and update that copy.
   * @returns
   */
  #removeKeysFromUserDetails = (user, options) => {
    const isCorrestUser = user !== null && user && typeof user === "object";
    if (!isCorrestUser) return;
    const { keys, createNewCopy = false } = options || {};
    const userCopy = createNewCopy ? JSON.parse(JSON.stringify(user)) : user;
    const finalKeys = ["privateData", "updatedAt"];
    if (keys !== null && typeof keys === "object" && Array.isArray(keys)) {
      finalKeys.push(...keys);
    }

    const isNestedKey = (key) => key.includes(".");
    function removeNestedKeys(obj, key) {
      const keys = key.split(".");
      let current = obj,
        i;
      const keysLen = keys.length;
      for (i = 0; i < keysLen - 1; i++) {
        const keyValue = current[keys[i]];
        const hasCorrectValue = keyValue && typeof keyValue === "object";
        if (!hasCorrectValue) return;
        current = current[keys[i]];
      }
      const keyToDelete = keys[keysLen - 1];
      if (current.hasOwnProperty(keyToDelete)) delete current[keyToDelete];
    }
    function removeKey(user, keys) {
      const isCorrectUserType = user && typeof user === "object";
      if (!isCorrectUserType) return;
      if (Array.isArray(user)) {
        user.forEach((usr) => removeKey(usr, keys));
      } else {
        let key;
        for (key of finalKeys) {
          if (isNestedKey(key)) {
            removeNestedKeys(user, key);
          } else {
            if (user.hasOwnProperty(key)) delete user[key];
          }
        }
      }
    }
    removeKey(userCopy, finalKeys);
    if (createNewCopy) {
      return userCopy;
    }
  };

  //================ verification helpers =================//
  #verifyUserLogin = async (
    req,
    customValidation,
    validationLabelName,
    jwtOptnFrIpValidation,
    sendTokenFrIpValidation
  ) => {
    const requestBody = req.body || {};
    const authKeyValue = requestBody[this.#authKeyName];
    const query = { [this.#authKeyName]: authKeyValue };
    const userNotFoundMsg = `User with given ${this.#authKeyName} does not exists. Please sign up with given ${this.#authKeyName}.`;
    const user = await this.#getUserByQuery(query, true, userNotFoundMsg);
    const authUser = getUserDetailsFrmMongo(user);
    await this.#verifyUserFrstAndSecndAuthKey(
      requestBody,
      authUser,
      customValidation,
      validationLabelName
    );

    const userSource = getReqUserSource(req);
    const tokenDetails = await createAccessFrmRefreshToken(
      authUser.refreshToken,
      this.#jwtSecret,
      this.#encryptSecret,
      this.#jwtOptions
    );
    const userNewDetails = await this.#createNewCsrfToken(authUser.id);
    if (this.#disableIpMismatchValidation) {
      req.adminUser = removeUnnecessayUserDetails(user, true);
      req.user = removeUnnecessayUserDetails(userNewDetails);
      req.csrfToken = userNewDetails.csrfToken;
      return tokenDetails;
    }
    const userAllowedIpAddr = await this.#userSourceModel
      .findOne({ userId: authUser.id, ...userSource })
      .exec();

    if (!userAllowedIpAddr) {
      if (typeof sendTokenFrIpValidation === "function") {
        await this.#ipValidationTokenHelper(
          authUser,
          userSource,
          jwtOptnFrIpValidation,
          sendTokenFrIpValidation
        );
      }
      return null;
    }
    req.adminUser = removeUnnecessayUserDetails(user, true);
    req.user = removeUnnecessayUserDetails(userNewDetails);
    req.csrfToken = userNewDetails.csrfToken;
    return tokenDetails;
  };

  #verifyThirdPartyUserLogin = async (req) => {
    const requestBody = req.body || {};
    const authKeyValue = requestBody.email;
    const { thirdPartyProvider } = requestBody;
    const thirdPartyConfig = this.#thirdPartyLoginOption[thirdPartyProvider];
    if (!thirdPartyConfig.isPasswordRequired) {
      delete requestBody.password;
    }
    const query = { [this.#authKeyName]: authKeyValue };
    const userSource = getReqUserSource(req);
    let user = await this.#getUserByQuery(query, false, "");
    if (!user) {
      user = await this.#createNewUser(
        authKeyValue,
        requestBody,
        userSource,
        true
      );
    }
    const authUser = getUserDetailsFrmMongo(user);
    const tokenDetails = await createAccessFrmRefreshToken(
      authUser.refreshToken,
      this.#jwtSecret,
      this.#encryptSecret,
      this.#jwtOptions
    );
    const userNewDetails = await this.#createNewCsrfToken(authUser.id);
    if (this.#disableIpMismatchValidation) {
      req.adminUser = removeUnnecessayUserDetails(user, true);
      req.user = removeUnnecessayUserDetails(userNewDetails);
      req.csrfToken = userNewDetails.csrfToken;
      return tokenDetails;
    }
    const userAllowedIpAddr = await this.#userSourceModel
      .findOne({ userId: authUser.id, ...userSource })
      .exec();

    if (!userAllowedIpAddr) {
      if (typeof sendTokenFrIpValidation === "function") {
        await this.#ipValidationTokenHelper(
          authUser,
          userSource,
          jwtOptnFrIpValidation,
          sendTokenFrIpValidation
        );
      }
      return null;
    }
    req.adminUser = removeUnnecessayUserDetails(user, true);
    req.user = removeUnnecessayUserDetails(userNewDetails);
    req.csrfToken = userNewDetails.csrfToken;
    return tokenDetails;
  };

  async #ipValidationTokenHelper(
    user,
    userIpSource,
    jwtOptnFrIpValidation,
    tokenSenderCb
  ) {
    const propJwtOptionmaybe = isValidObject(jwtOptnFrIpValidation)
      ? { expiresIn: jwtOptnFrIpValidation.expiresIn }
      : {};
    const jwtOptions = Object.assign(
      {},
      JWT_OPTIONS,
      this.#jwtOptions,
      propJwtOptionmaybe,
      {
        expiresIn: JWT_EXPIRES_IN_TIME,
      }
    );
    const userPayload = { userId: user.id, ...userIpSource };
    const { token: shortToken, expiresIn: tokenExpiresIn } =
      await this.#generateValidationToken(
        user.id,
        tokenValidationType.ipCheck,
        userPayload,
        jwtOptions
      );
    await tokenSenderCb(shortToken, tokenExpiresIn, {
      ...removeUnnecessayUserDetails(user),
      ...userIpSource,
    });
  }

  async #verifyToken(
    cookieToken,
    throwErrorOnAccessTokenExpire = true,
    createNewAccessTokenOnExpires = false
  ) {
    const { refreshToken, accessToken } = cookieToken;
    const hasValidTokenDetails =
      !!refreshToken &&
      !!accessToken &&
      typeof refreshToken === "string" &&
      typeof accessToken === "string";
    if (!hasValidTokenDetails) {
      this.#createAndThrowError(INVALID_TOKEN_DETAILS, 401);
    }
    const rawRefreshToken = decryptString(refreshToken, this.#encryptSecret);
    const [accessTokenValue, refreshTokenValue] = await Promise.all([
      this.#checkToken(accessToken),
      this.#checkToken(rawRefreshToken),
    ]);
    const hasAccessTokenExpire = accessTokenValue.isExpired;
    const hasRefershTokenExpire = refreshTokenValue.isExpired;

    if (hasRefershTokenExpire) {
      const err = new Error();
      err.name = "TokenExpiredError";
      err.message = SESSION_EXPIRE_MESSAGE;
      throw err;
    }
    if (hasAccessTokenExpire && throwErrorOnAccessTokenExpire) {
      const err = new Error();
      err.name = "TokenExpiredError";
      err.message = SESSION_EXPIRE_MESSAGE;
      throw err;
    }
    const tokenDetailsMaybe = {};
    if (createNewAccessTokenOnExpires && hasAccessTokenExpire) {
      tokenDetailsMaybe.tokenDetails = await createAccessFrmRefreshToken(
        refreshToken,
        this.#jwtSecret,
        this.#encryptSecret,
        this.#jwtOptions
      );
    }
    const user = await this.#model
      .findOne({ id: accessTokenValue.id }, null, {
        lean: true,
      })
      .exec();
    if (!user) return null;
    return Object.assign({}, getUserDetailsFrmMongo(user), tokenDetailsMaybe);
  }

  async #verifyIpAddr(
    userId,
    ipAddr,
    browser,
    throwErrorOnNewAddr = true,
    errorMsg = NEW_IP_ADDR_FOUND
  ) {
    const savedIpAddr = await this.#userSourceModel
      .findOne({ userId, ipAddr, browser })
      .exec();

    if (!savedIpAddr && throwErrorOnNewAddr) {
      this.#createAndThrowError(errorMsg || NEW_IP_ADDR_FOUND, 401);
    }
    return savedIpAddr;
  }

  async #verifyCsrfToken(
    csrfToken,
    refCsrfToken,
    throwErrorOnInvalidCsrfToken = true,
    errorMsg = INVALID_CSRF_TOKEN
  ) {
    try {
      const { status: isCsrfTokenValid, isExpired } = await isValidCsrfToken(
        csrfToken,
        refCsrfToken,
        this.#encryptSecret
      );
      if (!isCsrfTokenValid && throwErrorOnInvalidCsrfToken) {
        this.#createAndThrowError(errorMsg || INVALID_CSRF_TOKEN, 401);
      }
      return { status: isCsrfTokenValid, isExpired };
    } catch (e) {
      if (throwErrorOnInvalidCsrfToken) {
        this.#createAndThrowError(errorMsg || INVALID_CSRF_TOKEN, 401);
      }
      return { status: false };
    }
  }

  async #checkToken(token) {
    try {
      const decoded = await decodeJwtToken(token, this.#jwtSecret);
      return { ...decoded, isExpired: false };
    } catch (e) {
      if (e && e.name && JWT_ERROR.has(e.name)) {
        const decoded = decodeJwtTokenWithoutValidation(token);
        return { ...decoded, isExpired: true };
      }
      throw e;
    }
  }

  /**
   * @param {Request} req
   * @param {object} options
   * @param {string} options.userId
   * @param {string} options.csrfToken
   * @param {boolean} [options.throwErrOnNewIpAddr]
   * @param {boolean} [options.throwErrorOnInvalidCsrfToken]
   * @param {string} [options.newIpAddrErrMsg]
   * @param {string} [options.invalidCsrfTokenErrMsg]
   */
  async #verifyUserIpAddrAndCsrfToken(req, options) {
    const {
      throwErrOnNewIpAddr = true,
      throwErrorOnInvalidCsrfToken = true,
      newIpAddrErrMsg,
      invalidCsrfTokenErrMsg,
      userId,
      csrfToken,
    } = options;
    const extraValidationStatus = {
      isIpAddrValid: this.#disableIpMismatchValidation,
      isCsrfTokenValid: this.#disableCSRFTokenValidation,
      isCsrfTokenExpired: false,
    };
    if (!extraValidationStatus.isCsrfTokenValid) {
      const reqUserCsrfToken = getReqUserCsrfToken(req);
      const { status, isExpired = false } = await this.#verifyCsrfToken(
        reqUserCsrfToken,
        csrfToken,
        throwErrorOnInvalidCsrfToken,
        invalidCsrfTokenErrMsg
      );
      extraValidationStatus.isCsrfTokenValid = status;
      extraValidationStatus.isCsrfTokenExpired = isExpired;
    }
    if (!extraValidationStatus.isIpAddrValid) {
      const userSource = getReqUserSource(req);
      extraValidationStatus.isIpAddrValid = await this.#verifyIpAddr(
        userId,
        userSource.ipAddr,
        userSource.browser,
        throwErrOnNewIpAddr,
        newIpAddrErrMsg
      );
    }
    return { ...extraValidationStatus };
  }

  async #verifyUserFrstAndSecndAuthKey(
    requestBody,
    refUser,
    customValidation,
    validationLabelName
  ) {
    const authValue = requestBody[this.#authKeyName];
    const password = requestBody.password;
    const isVaidRefUserPwd =
      refUser.password && typeof refUser.password === "string";
    if (!authValue || !isVaidRefUserPwd) {
      this.#createAndThrowError("Invalid user authentication details.", 401);
    }
    let isUserVerified = false;
    const isSameAuthkeyValue = authValue === refUser[this.#authKeyName];
    if (!!password) {
      isUserVerified = await isUserPasswordSame(password, refUser.password);
    } else if (
      this.#disablePasswordValidation &&
      typeof customValidation === "function"
    ) {
      isUserVerified = await customValidation(requestBody, refUser);
    }
    isUserVerified = isUserVerified && isSameAuthkeyValue;

    if (!isUserVerified) {
      const secndValidationLabelName = !!password
        ? " and password"
        : this.#disablePasswordValidation &&
            typeof validationLabelName === "string"
          ? ` and ${validationLabelName}`
          : "";
      const msg = `The ${this.#authKeyName}${secndValidationLabelName} you provided don't match our records. Please double-check and try again.`;

      this.#createAndThrowError(msg, 401);
    }
  }
  /**
   * @param {Request} req
   * @param {object} options
   * @param {boolean} [options.throwErrorOnAccessTokenExpire]
   * @param {boolean} [options.createNewAccessTokenOnExpires]
   * @param {boolean} [options.includeUserCsrfToken]
   * @param {boolean} [options.throwErrOnNewIpAddr]
   * @param {boolean} [options.throwErrorOnInvalidCsrfToken]
   * @param {string} [options.newIpAddrErrMsg]
   * @param {string} [options.invalidCsrfTokenErrMsg]
   *
   */
  #validateUserAuthentication = async (req, options = {}) => {
    const {
      includeUserCsrfToken,
      throwErrorOnAccessTokenExpire,
      createNewAccessTokenOnExpires,
      ...rest
    } = options;
    const cookieDetail = getUserCookies(req, this.#cookieId);
    const user = await this.#verifyToken(
      cookieDetail,
      throwErrorOnAccessTokenExpire,
      createNewAccessTokenOnExpires
    );
    if (!user) {
      this.#createAndThrowError(NEED_AUTHENTICATION_BEFORE_USE, 401);
    }
    const tokenOptions = {
      ...rest,
      userId: user.id,
      csrfToken: includeUserCsrfToken ? user.csrfToken : null,
    };
    const extraData = await this.#verifyUserIpAddrAndCsrfToken(
      req,
      tokenOptions
    );
    return { user, ...extraData };
  };

  // ============ validation token helper===================//
  #generateValidationToken = async (
    userId,
    validationType,
    userPayload,
    jwtOptions = {}
  ) => {
    if (!userId) {
      this.#createAndThrowError(
        "cannot generate validation token without a userId",
        400
      );
    }
    const isValidationCorrect = tokenValidationValuesSet.has(validationType);
    if (!isValidationCorrect) {
      this.#createAndThrowError("Validation type not supported", 400);
    }
    const validUserPayload =
      typeof userPayload === "object" && userPayload.constructor === Object
        ? userPayload
        : {};
    const curDate = new Date();
    let tokenExpireDate = null;
    let validationToken = await this.#validationTokenModel
      .findOne(
        { userId, type: validationType, expiresIn: { $gte: curDate } },
        null,
        {
          lean: true,
        }
      )
      .exec();
    if (validationToken && validationToken._id && validationToken.expiresIn) {
      tokenExpireDate = new Date(validationToken.expiresIn);
    }
    if (!validationToken) {
      const token = await createJwtToken(
        validUserPayload,
        this.#jwtSecret,
        jwtOptions
      );
      const encodedToken = encryptString(token, this.#encryptSecret);
      const { exp } = await decodeJwtToken(token, this.#jwtSecret);
      const expireDate = new Date(exp * 1000);
      tokenExpireDate = expireDate;
      await this.#validationTokenModel
        .findOneAndDelete({
          userId,
          type: validationType,
        })
        .exec();
      validationToken = await this.#validationTokenModel.findOneAndUpdate(
        {
          userId,
          type: validationType,
        },
        { longToken: encodedToken, expiresIn: expireDate },
        { lean: true, new: true, upsert: true }
      );
    }
    const shortToken = encodeToBase64(validationToken._id.toString());
    return { token: shortToken, expiresIn: tokenExpireDate };
  };

  #verifyValidationToken = async (token, invalidTokenMsg, noTokenMsg) => {
    try {
      const id = decodeFrmBase64(token);
      const isValidId = mongoose.isValidObjectId(id);
      if (!isValidId) {
        const msg = invalidTokenMsg || "Invalid value.";
        this.#createAndThrowError(msg, 400);
      }
      const tokeRef = await this.#validationTokenModel.findById(id, null, {
        lean: true,
      });
      if (!tokeRef) {
        const msg = noTokenMsg || "Invalid value.";
        this.#createAndThrowError(msg, 400);
      }
      const { longToken } = tokeRef;
      const decodedToken = decryptString(longToken, this.#encryptSecret);
      const userPayload = await decodeJwtToken(decodedToken, this.#jwtSecret);
      return userPayload;
    } catch (e) {
      if (e && e.name && TOTAL_JWT_ERROR.has(e.name)) {
        const error = new Error();
        error.name = e.name;
        error.message =
          "Validation token has expired or invalid. Please create a new token and try again.";
        throw error;
      }
      throw e;
    }
  };

  #removeValidationToken = async (token, invalidTokenMsg) => {
    const id = decodeFrmBase64(token);
    const isValidId = mongoose.isValidObjectId(id);
    if (!isValidId) {
      const msg = invalidTokenMsg || "Invalid value.";
      this.#createAndThrowError(msg, 400);
    }
    await this.#validationTokenModel.findByIdAndDelete(id);
  };

  //============error helper=====================//
  #errorRespWrapper(resp, func) {
    return (...args) => {
      try {
        return func(...args);
      } catch (err) {
        resp.status(400).send(err.message);
      }
    };
  }

  #errorHandler(err, res, errorHandler, defaultMessage) {
    if (typeof errorHandler === "function") {
      errorHandler(err, res);
      return;
    }
    const message = err?.message || defaultMessage;
    const status = err?.status || 400;
    return res.status(status).send(message);
  }

  #validationErrorHandler(validationResult) {
    let errorMessage = "";
    if (
      validationResult &&
      validationResult.error &&
      validationResult.error.details &&
      Array.isArray(validationResult.error.details)
    ) {
      const errorDetails = validationResult.error.details;
      errorMessage = errorDetails.reduce((acc, detail, indx) => {
        if (indx > 0) {
          acc += " and ";
        }
        acc += `${detail.message}`;
        return acc;
      }, "");
      errorMessage = `${errorMessage}.`;
    }
    return errorMessage;
  }

  #createAndThrowError(msg, status) {
    const error = new Error();
    error.message = msg;
    error.status = status;
    throw error;
  }

  //================ object sanitizer ==================//
  #sanitizeValue = (value) => {
    if (typeof value === "string") {
      value = validator.trim(value);
      value = validator.isURL(value) ? value : validator.escape(value);
      if (validator.isEmail(value)) {
        value = validator.normalizeEmail(value);
      }
    } else if (typeof value === "object" && value !== null) {
      if (Array.isArray(value)) {
        value = value.map(this.#sanitizeObject.bind(this));
      } else {
        value = this.#sanitizeObject(value);
      }
    }
    return value;
  };

  #unSanitizeValue = (value) => {
    if (typeof value === "string") {
      value = validator.unescape(value);
    } else if (typeof value === "object" && value !== null) {
      if (Array.isArray(value)) {
        value = value.map(this.#unsanitizeObject.bind(this));
      } else {
        value = this.#unsanitizeObject(value);
      }
    }
    return value;
  };

  #sanitizeObject = (obj) => {
    if (!this.#sanitizeObjectBeforeAdd) return obj;
    const isObjectType = typeof obj === "object" && obj !== null;
    if (!isObjectType) return this.#sanitizeValue(obj);
    if (Array.isArray(obj)) {
      return obj.map(this.#sanitizeValue.bind(this));
    }
    if (obj.constructor === Object) {
      const sanitizeObj = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          sanitizeObj[key] = this.#sanitizeValue(obj[key]);
        }
      }
      return sanitizeObj;
    }
    if (typeof obj.toString === "function") {
      return this.#sanitizeValue(obj.toString());
    }
    return obj;
  };

  /**
   *
   * @param {object} sanitizeObject
   * @returns {object}
   */
  #unsanitizeObject = (sanitizeObject) => {
    const isObjectType =
      typeof sanitizeObject === "object" && sanitizeObject !== null;
    if (!isObjectType) return this.#unSanitizeValue(sanitizeObject);
    if (Array.isArray(sanitizeObject)) {
      return obj.map(this.#unSanitizeValue.bind(this));
    }
    if (sanitizeObject.constructor === Object) {
      const sanitizeObj = {};
      for (const key in sanitizeObject) {
        if (sanitizeObject.hasOwnProperty(key)) {
          sanitizeObj[key] = this.#unSanitizeValue(sanitizeObject[key]);
        }
      }
      return sanitizeObj;
    }
    if (typeof sanitizeObject.toString === "function") {
      return this.#unSanitizeValue(obj.toString());
    }
    return sanitizeObject;
  };

  middlewares() {
    return {
      signupMiddleware: this.#signupMiddlware,
      loginMiddleware: this.#loginMiddleware,
      thirdPartyLoginMiddleware: this.#thirdPartyLoginMiddleware,
      logoutMiddleware: this.#logoutMiddleware,
      newIpAddrCheckMiddleware: this.#newIpAddrCheckMiddleware,
      newCsrfTokenMiddleware: this.#newCsrfTokenMiddleware,
      verifyUserTokenMiddleware: this.#verifyUserTokenMiddleware,
      getCurrentUserMiddleware: this.#verifyUserTokenMiddleware,
      deleteCurrentUserMiddleware: this.#deleteCurrentUserMiddleware,
      changeAuthenticationValueMiddleware:
        this.#changeAuthenticationValueMiddleware,
      changePasswordMiddleware: this.#changePasswordMiddleware,
      resetPasswordMiddleware: this.#resetPasswordMiddleware,
      resetPasswordVerifyMiddleware: this.#resetPasswordVerifyMiddleware,
      generateTokenForAuthVerificationMiddleware:
        this.#generateTokenForAuthVerificationMiddleware,
      validateTokenForAuthVerificationMiddleware:
        this.#validateTokenForAuthVerificationMiddleware,
    };
  }

  helpers() {
    return {
      getUserDetails: this.#getUserByQueryHelper,
      getUserDetailsWithAdminData: this.#getUserDetailsAdminData,
      updateUserDetails: this.#updateUserByQueryHelper,
      removeKeysFromUserDetails: this.#removeKeysFromUserDetails,
      getUsersDetails: this.#getUsersByQueryHelper,
      getUsersDetailsWithAdminData: this.#getUsersByQueryHelperForAdminData,
      generateAuthVerificationToken: this.#generateAuthVerificationToken,
      unsanitizeObject: this.#unsanitizeObject,
    };
  }
}

module.exports = { PlugableAuthentication };
