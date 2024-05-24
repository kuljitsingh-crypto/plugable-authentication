const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { EventEmitter } = require("events");
const { isEmpty, includes } = require("lodash");
const CryptoJS = require("crypto-js");
const validator = require("validator");

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
      ...(disablePasswordValidation
        ? {}
        : { password: { type: String, required: true } }),
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
//11) get current user details -
//12) delete curren user -

class PlugableAuthentication {
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
  #sentizeObjectBeforeAdd = true;

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
   * refreshToken:string,
   * csrfToken:string,
   * metadata?:object,
   * password?: string,browser:string,ipAddr:string})=>Promise<void>} [options.tokenSenderFrIpValidationCb] - defualt null
   * @param {string} [options.csrfTokenExpireTime] - default null Ex:"10h"/"7d"
   * @param {boolean} [options.verifyAuthKeyOnCreation] - default false.
   * If you want to mark your authentication key as verified on creation. set as true.
   * @param {boolean} [options.sentizeObjectBeforeAdd] - default true.
   * Santize metadata,privateData and publicData before adding to the database.
   */
  constructor(options) {
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
      tokenSenderFrIpValidationCb,
      csrfTokenExpireTime,
      verifyAuthKeyOnCreation,
      sentizeObjectBeforeAdd,
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
    if (typeof tokenSenderFrIpValidationCb === "function") {
      this.#tokenSenderFrIpValidationCb = tokenSenderFrIpValidationCb;
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
      typeof sentizeObjectBeforeAdd === "boolean" &&
      sentizeObjectBeforeAdd === false
    ) {
      this.#sentizeObjectBeforeAdd = sentizeObjectBeforeAdd;
    }
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
          return res.status(400).send(errorMessage);
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
          return res.status(400).send(msg);
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
   * @param {object} options
   * @param {(err:Error,resp:object)=>void} [options.errorHandler]
   *
   */
  #signupMiddlware = (options) => {
    return async (req, res, next) => {
      await this.#waitUntilModelReady();
      const { errorHandler } = options || {};
      try {
        const errorMessage = this.#validateRequestData(req);
        if (errorMessage) {
          return res.status(400).send(errorMessage);
        }
        await this.#createUser(req);
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
          const msg = "Cannot add new IP address. Missing a required value.";
          return res.status(400).send(msg);
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
          throw new Error(NEED_AUTHENTICATION_BEFORE_USE);
        }
        await this.#verifyUserIpAddrAndCsrfToken(req, {
          userId: user.id,
          csrfToken: user.csrfToken,
          newIpAddrErrMsg: NEW_IP_ADDR_DURING_LOG_OUT,
        });
        req.user = getUserDetailsFrmMongo(user);
        req.csrfToken = user.csrfToken;
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
        const cookieDetail = getUserCookies(req, this.#cookieId);
        const user = await this.#verifyToken(cookieDetail, false);
        if (!user) {
          throw new Error(NEED_AUTHENTICATION_BEFORE_USE);
        }
        await this.#verifyUserIpAddrAndCsrfToken(req, {
          userId: user.id,
          csrfToken: null,
          throwErrorOnInvalidCsrfToken: false,
        });
        const userId = user.id;
        const userNewDetails = await this.#createNewCsrfToken(userId);
        req.user = userNewDetails;
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
        const cookieDetail = getUserCookies(req, this.#cookieId);

        const user = await this.#verifyToken(cookieDetail, false, true);
        if (!user) {
          throw new Error(NEED_AUTHENTICATION_BEFORE_USE);
        }
        const { isCsrfTokenExpired } = await this.#verifyUserIpAddrAndCsrfToken(
          req,
          {
            userId: user.id,
            csrfToken: user.csrfToken,
          }
        );
        const { tokenDetails, ...restUserDetails } = user;
        const newUserDetails = await this.#checkAndCreateNewCsrfToken(
          restUserDetails,
          isCsrfTokenExpired
        );
        req.user = newUserDetails;
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
        const cookieDetail = getUserCookies(req, this.#cookieId);

        const user = await this.#verifyToken(cookieDetail, false, true);
        if (!user) {
          throw new Error(NEED_AUTHENTICATION_BEFORE_USE);
        }
        await this.#verifyUserIpAddrAndCsrfToken(req, {
          userId: user.id,
          csrfToken: user.csrfToken,
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
        req.user = user;
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
          return res.status(400).send(errorMessage);
        }
        const { oldAuth, newAuth } = req.body;
        if (oldAuth === newAuth) {
          return res
            .status(400)
            .send(
              "Your old and new authentication information must different."
            );
        }
        const cookieDetail = getUserCookies(req, this.#cookieId);
        const user = await this.#verifyToken(cookieDetail, false, true);
        if (!user) {
          throw new Error(NEED_AUTHENTICATION_BEFORE_USE);
        }
        const { isCsrfTokenExpired } = await this.#verifyUserIpAddrAndCsrfToken(
          req,
          {
            userId: user.id,
            csrfToken: user.csrfToken,
          }
        );

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
        req.user = restUserDetails;
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
          return res.status(400).send(errorMessage);
        }

        const cookieDetail = getUserCookies(req, this.#cookieId);
        const user = await this.#verifyToken(cookieDetail, false, true);
        if (!user) {
          throw new Error(NEED_AUTHENTICATION_BEFORE_USE);
        }
        const { isCsrfTokenExpired } = await this.#verifyUserIpAddrAndCsrfToken(
          req,
          {
            userId: user.id,
            csrfToken: user.csrfToken,
          }
        );
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
          return res
            .status(400)
            .send("New password must be different from previous one.");
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
        req.user = restUserDetails;
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
          return res.status(400).send(errorMessage);
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
        req.user = preSavedUser;
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
          return res.status(400).send(errorMessage);
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
          return res.status(400).send(msg);
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
        req.user = newUserDetails;
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
          return res.status(400).send(errorMessage);
        }
        const { auth } = req.body || {};
        const preSavedUser = await this.#getUserByQuery(
          { [this.#authKeyName]: auth },
          true
        );
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
        req.validationToken = shortToken;
        req.user = preSavedUser;
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
          return res.status(400).send(errorMessage);
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
        const savedAuthValue = userPayload[this.#authKeyName];
        const tokenType = userPayload.tokenType;
        const userId = userPayload.id;
        if (
          savedAuthValue !== auth ||
          tokenType !== tokenValidationType.authCheck
        ) {
          const msg = `User's ${this.#authKeyName} does not match with requested one. Please double check and try again.`;
          return res.status(400).send(msg);
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
        req.user = newUserDetails;
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
  #validateRequestData(requestBody) {
    const validationResult = this.#dataValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateChangeAuthRequestData(requestBody) {
    const validationResult = this.#changeAuthValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateChangePwdRequestData(requestBody) {
    const validationResult = this.#changePwdValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateResetPwdRequestData(requestBody) {
    const validationResult = this.#resetPwdValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateResetPwdVerifyRequestData(requestBody) {
    const validationResult = this.#resetPwdVerifyValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateVerifyAuthGenRequestData(requestBody) {
    const validationResult = this.#verifyAuthGenValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  #validateVerifyAuthVerRequestData(requestBody) {
    const validationResult = this.#verifyAuthVerValidationSchema.validate(
      requestBody || {}
    );
    const errorMessage = this.#validationErrorHandler(validationResult);
    return errorMessage;
  }

  //==============user helper==================//
  /**
   * @param {object} details
   * @param {{auth?:string,id?:string,metadata?:object,privateData?:object,publicData?:object}} details.query -
   * auth value is used like this email=auth,if authKeyName='email'.
   * For metadata, publicData or privateData, use like this metadata:{key:string,'a.b':number}
   * @param {boolean} [details.throwErrOnUserNotFound]
   * @param {string} [details.userNotFoundMsg]
   */
  #getUserByQueryHelper = async (details) => {
    const isValidDetails = isValidObject(details);
    if (!isValidDetails) return null;

    const {
      query,
      throwErrOnUserNotFound = false,
      userNotFoundMsg = "",
    } = details || {};

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
    await this.#waitUntilModelReady();
    return this.#getUserByQuery(
      correctQuery,
      throwErrOnUserNotFound,
      userNotFoundMsg
    );
  };

  /**
   * @param {{auth?:string,id?:string,metadata?:object}} updateQuery - auth value is used like this email=auth,if authKeyName='email'.
   * @param {{metadata?:object}} updateData
   */
  #updateUserByQueryHelper = async (updateQuery, updateData) => {
    const isValidParams =
      isValidObject(updateQuery) && isValidObject(updateData);

    if (!isValidParams) return null;
    const user = await this.#getUserByQueryHelper({
      query: updateQuery,
      throwErrOnUserNotFound: false,
    });
    if (!user) return null;
    const { metadata, publidData, privateData } = updateData;
    const extraUpdateData = {
      metadata: isValidObject(metadata)
        ? { ...user.metadata, ...this.#santizeObject(metadata) }
        : user.metadata,
      publidData: isValidObject(publidData)
        ? { ...user.publidData, ...this.#santizeObject(publidData) }
        : user.publidData,
      privateData: isValidObject(privateData)
        ? { ...user, ...this.#santizeObject(privateData) }
        : user.privateData,
    };

    await this.#waitUntilModelReady();
    return this.#updateUserByQuery({ id: user.id }, { $set: extraUpdateData });
  };

  #getUserByQuery = async (
    query,
    throwErrOnUserNotFound = true,
    userNotFoundMsg = ""
  ) => {
    const user = await this.#model.findOne(query, null, { lean: true }).exec();
    if (!user && throwErrOnUserNotFound) {
      const msg =
        userNotFoundMsg ||
        `User with given ${this.#authKeyName} does not exists. Please double-check and try again.`;
      throw new Error(msg);
    }
    return user ? getUserDetailsFrmMongo(user) : null;
  };

  #createUser = async (req) => {
    const requestBody = req.body || {};
    const authKeyValue = requestBody[this.#authKeyName];
    const preSavedUser = await this.#model
      .findOne({ [this.#authKeyName]: authKeyValue })
      .exec();

    if (!!preSavedUser) {
      const msg = `User with given ${this.#authKeyName} already exists. Please log in with your registered ${this.#authKeyName}.`;
      throw new Error(msg);
    }
    const { publidData, privateData, metadata, password } = requestBody;
    const hashPassword = {};
    if (!!password) {
      hashPassword.password = await createHashPasswword(password);
    }
    const extraDataMaybe = {
      publicData: isValidObject(publidData)
        ? this.#santizeObject(publidData)
        : {},
      privateData: isValidObject(privateData)
        ? this.#santizeObject(privateData)
        : {},
      metadata: isValidObject(metadata) ? this.#santizeObject(metadata) : {},
    };

    const userId = uuidv4();
    const userPayload = { id: userId, ...EXTRA_USER_PAYLOAD_FOR_TOKEN };
    const userSource = getReqUserSource(req);

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
      isVerified: this.#verifyAuthKeyOnCreation,
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
    const userDetails = getUserDetailsFrmMongo(newUser, true);
    req.user = { ...userDetails };
    req.csrfToken = csrfToken;
  };

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

  #excludeUserPrivateData = (user) => {
    const { privateData, ...rest } = user;
    return rest;
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
      req.user = { ...userNewDetails };
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
    req.user = getUserDetailsFrmMongo(userNewDetails);
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
      ...user,
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
      throw new Error(INVALID_TOKEN_DETAILS);
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
      throw new Error(errorMsg || NEW_IP_ADDR_FOUND);
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
        throw new Error(errorMsg || INVALID_CSRF_TOKEN);
      }
      return { status: isCsrfTokenValid, isExpired };
    } catch (e) {
      if (throwErrorOnInvalidCsrfToken) {
        throw new Error(errorMsg || INVALID_CSRF_TOKEN);
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
    if (!authValue) {
      throw new Error("Invalid user authentication details.");
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

      throw new Error(msg);
    }
  }

  // ============ validation token helper===================//
  #generateValidationToken = async (
    userId,
    validationType,
    userPayload,
    jwtOptions = {}
  ) => {
    if (!userId) {
      throw new Error("cannot generate validation token without a userId");
    }
    const isValidationCorrect = tokenValidationValuesSet.has(validationType);
    if (!isValidationCorrect) {
      throw new Error("Validation type not supported");
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
        throw new Error(msg);
      }
      const tokeRef = await this.#validationTokenModel.findById(id, null, {
        lean: true,
      });
      if (!tokeRef) {
        const msg = noTokenMsg || "Invalid value.";
        throw new Error(msg);
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
      throw new Error(msg);
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
    return res.status(400).send(message);
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

  //================ object santizer ==================//
  #santizeValue(value) {
    if (typeof value === "string") {
      value = validator.trim(value);
      value = validator.escape(value);
      if (validator.isEmail(value)) {
        value = validator.normalizeEmail(value);
      }
    } else if (typeof value === "object" && obj !== null) {
      if (Array.isArray(value)) {
        value = value.map(this.#santizeObject);
      } else {
        value = this.#santizeObject(value);
      }
    }
    return value;
  }

  #santizeObject(obj) {
    if (!this.#sentizeObjectBeforeAdd) return obj;
    if (typeof obj === "object" && obj !== null) {
      if (Array.isArray(obj)) {
        return obj.map(this.#santizeValue);
      } else {
        const santizeObj = {};
        for (const key in obj) {
          if (obj.hasOwnProperty(key)) {
            santizeObj[key] = this.#santizeValue(obj[key]);
          }
        }
        return santizeObj;
      }
    }
    return this.#santizeValue(obj);
  }

  middlewares() {
    return {
      signupMiddleware: this.#signupMiddlware,
      loginMiddleware: this.#loginMiddleware,
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
      updateUserDetails: this.#updateUserByQueryHelper,
      removePrivateDataFromUserDetails: this.#excludeUserPrivateData,
      //add two methods getUsersDetails and updateUsersDetails
    };
  }
}

module.exports = { PlugableAuthentication };
