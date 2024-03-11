require("dotenv").config();
const mongoose = require("mongoose");
const { PlugableAuthentication } = require("../index");

const mongoUri = process.env.MONGO_TEST_URI;
const mongoConfig = async () => {
  try {
    if (!mongoUri) throw new Error("No Mongo URI Found");
    await mongoose.connect(mongoUri);
    console.log("Connected to Mongo DB");
  } catch (e) {
    console.error("Failed to connect to Mongo DB", err);
  }
};

mongoConfig();

const cookieStoreConnection = () => {
  const cookieStoreSchema = new mongoose.Schema(
    {
      cookieName: String,
      cookieValue: String,
    },
    { timestamps: true }
  );

  const CookieStore = mongoose.model("cookieStore", cookieStoreSchema);

  const addCookieToStore = async (cookieName, cookieValue) => {
    const data = await CookieStore.findOneAndUpdate(
      { cookieName },
      { cookieValue },
      { lean: true, new: true, upsert: true }
    ).exec();
    return { cookieName: data.cookieName, cookieValue: data.cookieValue };
  };

  const getCookieValueFrmStore = async (cookieName) => {
    const data = await CookieStore.findOne({ cookieName }, null, {
      lean: true,
    }).exec();

    return { cookieName: data.cookieName, cookieValue: data.cookieValue };
  };

  const getAllCookiesFrmStore = async () => {
    const datas = await CookieStore.find().exec();
    const dataObject = datas.reduce((prev, curnt) => {
      prev[curnt.cookieName] = curnt.cookieValue;
      return prev;
    }, {});
    return dataObject;
  };
  return { addCookieToStore, getCookieValueFrmStore, getAllCookiesFrmStore };
};

const { addCookieToStore, getCookieValueFrmStore, getAllCookiesFrmStore } =
  cookieStoreConnection();

const paInstanceCreator = (options) => {
  const paInstance = new PlugableAuthentication(options);
  return paInstance;
};

// module.exports.mongoConfig = mongoConfig;
module.exports.emptyPaInstanceCreator = () => {
  return paInstanceCreator();
};

module.exports.withOptionsPaInstanceCreator = (options) => {
  return function () {
    return paInstanceCreator(options);
  };
};

module.exports.paOptions = {
  uri: process.env.MONGO_TEST_URI,
  collectionName: process.env.MONGO_TEST_COLLECTION_NAME,
  jwtSecret: process.env.JWT_TEST_SECRET_KEY,
  encryptSecret: process.env.TEST_ENCRYPTION_SECRET_KEY,
  cookieId: process.env.TEST_COOKIE_ID,
};
module.exports.extraPaOptions = {
  authKeyName: "username",
  disableEmailValidation: true,
  authKeyValidationName: 'user name like "abc_dhe45" required',
  authKeyValidationPattern: "^[a-zA-Z0-9]+_[a-zA-Z0-9]+$",
};

module.exports.paOptionsForOtp = {
  disablePasswordValidation: true,
  // passwordValidationPattern: '^[0-9]{6}$',
  // passwordValidationName: 'otp must be 6 digits long',
};

module.exports.paOptionsForPhone = {
  authKeyName: "phoneNumber",
  disableEmailValidation: true,
  authKeyValidationName: 'Phone like "+11234567890" is required',
  authKeyValidationPattern: "^\\+[0-9]{11}$",
  disablePasswordValidation: true,
};

module.exports.requestMethod = {
  get: "get",
  post: "post",
};

/**
 * @param {object} details
 * @param {string} [details.userIp]
 * @param {string} [details.csrfToken]
 * @param {boolean} [details.disableUserCookie]
 */
module.exports.dummyExpress = (details) => {
  const { userIp, csrfToken, disableUserCookie = false } = details || {};
  const csrfTokenMaybe =
    !!csrfToken && typeof csrfToken === "string"
      ? { "x-csrf-token": csrfToken }
      : {};
  const request = {
      ip:
        typeof userIp === "string" && userIp
          ? userIp
          : process.env.TEST_USER_IP1,
      headers: { "user-agent": "dummy", ...csrfTokenMaybe },
      getUser() {
        return this.user;
      },
      getUserCsrfToken() {
        return this.getUserCsrfToken;
      },
      getValidationToken() {
        return this.validationToken;
      },
      getTokenExpiryTime() {
        return this.tokenExpiresIn;
      },
    },
    response = {
      __statusCode: 200,
      __msg: "",
      __cookieName: "",

      cookie(cookieName, details) {
        this.__cookieName = cookieName;
        addCookieToStore(
          cookieName,
          typeof details === "string" ? details : JSON.stringify(details)
        );
      },
      clearCookie(cookieName) {
        this.__cookieName = undefined;

        addCookieToStore(cookieName, undefined);
      },
      status(statusCode) {
        this.__statusCode = statusCode;
        return this;
      },
      send(msg) {
        this.__msg = msg;
      },
      getCookieName() {
        return this.__cookieName;
      },
      getResponseStatus() {
        if (this.__statusCode !== 200) {
          const err = new Error();
          err.status = this.__statusCode;
          err.message = this.__msg;
          console.log("Response status msg:", this.__msg);
          throw err;
        }
        return "ok";
      },
    };
  const next = () => {
    console.log("calling next handler");
  };

  return {
    getResponseStatus() {
      return response.getResponseStatus();
    },
    getCookieName() {
      return response.getCookieName();
    },
    getUserDetails() {
      return request.getUser();
    },
    getValidationToken() {
      return request.getValidationToken();
    },
    getTokenExpiryTime() {
      return request.getTokenExpiryTime();
    },
    getUserCsrfToken() {
      return request.getUserCsrfToken();
    },
    postHandler(middlewareCb, requestData) {
      if (typeof middlewareCb !== "function") {
        throw new Error("Callback function is required.");
      }

      return async (...args) => {
        const func = middlewareCb(...args);
        request.body = { ...requestData };
        const cookieStore = await (disableUserCookie
          ? Promise.resolve({})
          : getAllCookiesFrmStore());
        request.cookies = { ...cookieStore };
        return func(request, response, next);
      };
    },
    getHandler(middlewareCb, requestData) {
      if (typeof middlewareCb !== "function") {
        throw new Error("Callback function is required.");
      }
      return async (...args) => {
        const cookieStore = await getAllCookiesFrmStore();
        const func = middlewareCb(...args);
        request.query = { ...requestData };
        request.cookies = { ...cookieStore };
        return func(request, response, next);
      };
    },
  };

  return;
};

module.exports.getCookieStoreValue = async (cookieName) => {
  const data = await getCookieValueFrmStore(cookieName);
  return data.cookieValue;
};

module.exports.getTestUserEmailPwdCredential = () => {
  return {
    email: process.env.TEST_USER_EMAIL,
    password: process.env.TEST_USER_PWD,
  };
};

module.exports.getTestUserNamePwdCredential = () => {
  return {
    username: process.env.TEST_USER_NAME,
    password: process.env.TEST_USER_PWD,
  };
};

module.exports.getRandomeDigitOfLen = (len = 6) => {
  let digit = "";
  while (digit.length < len) {
    const randNumstr = Math.random().toString().substring(2).trim();
    digit += randNumstr;
  }
  return digit.substring(0, len);
};

module.exports.getTestUserEmailOtpCredential = () => {
  return {
    email: process.env.TEST_USER_EMAIL_FOR_OTP,
    otp: process.env.TEST_USER_EMAIL_OTP,
  };
};

module.exports.getTestUserPhoneOtpCredential = () => {
  return {
    phoneNumber: process.env.TEST_USER_PHONE_FOR_OTP,
    otp: process.env.TEST_USER_PHONE_OTP,
  };
};

module.exports.getTestUserPhoneOtpCredential2 = () => {
  return {
    phoneNumber: process.env.TEST_USER_PHONE_FOR_OTP2,
  };
};

module.exports.getFailedTestUserNamePwdCredential = () => {
  return {
    username: process.env.TEST_USER_FAILED_NAME,
    password: process.env.TEST_USER_PWD,
  };
};

/**
 * @param {string} fileName
 */
module.exports.isSingleTestFileExceutionMatchFile = (fileName) => {
  const args = process.argv.slice(2);
  const isSingleTestFileExceution = args.some((arg) => arg.includes("grep"));
  if (!isSingleTestFileExceution) return true;
  return args.some((arg) => fileName.includes(arg));
};

module.exports.userIpAddress = {
  ip1: process.env.TEST_USER_IP1,
  ip2: process.env.TEST_USER_IP2,
};
module.exports.userCsrfToken = {
  csrfToken1: process.env.TEST_USER_CSRF_TOKEN1,
};
module.exports.userPwd = {
  pwd1: process.env.TEST_USER_PWD1,
  pwd2: process.env.TEST_USER_PWD2,
};

module.exports.disablePaOptions = {
  disableCSRFTokenValidation: true,
  disableIpMismatchValidation: true,
};

module.exports.delayPromise = (time = 1000) => {
  return new Promise((resolve, reject) => {
    setInterval(resolve, time);
  });
};
