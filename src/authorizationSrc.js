const jwt = require('jsonwebtoken');
const randomstring = require('randomstring');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { logger } = require('../utils/logger');
const { checkRequiredParameters, srcFileErrorHandler } = require('../utils/srcFile');
const { sendEmailText } = require('../utils/email');
const db = require('../utils/db');
const { addUserVerificationCode, verifyUserVerificationCode, deleteUserVerificationCode } = require('./userVerificationSrc');
const { getUserByEmail } = require('./userSrc');

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

/**
 * @function addUserIP
 * @summary Add an ip to user ip addresses
 * @param {string} id User's id
 * @param {string} ip User's ip address
 * @returns {object} addUserIPResults
 * @throws {boolean} false
 */
const addUserIP = async function addUserIP(id, ip) {
  // Check if there is no id or password
  if (!id || !ip) throw { code: 400, message: 'Please provide required information' };

  // Add ip to user in the database
  return db.query('update users set ip = ip || $1 where id=$2 and not (ip @> ARRAY[$1]::inet[]) returning id', [ip, id], 'Add user ip');
};

/**
 * @function registerUser
 * @summary Register a new user and send a email verification link
 * @param {*} req http request contains user information
 * @returns {object} registerUserResults
 * @throws {object} errorCodeAndMsg
 */
const registerUser = async function registerUser(req) {
  let createdUserId = false;

  try {
    const {
      username,
      password,
      email,
      ip,
    } = req.body;

    await checkRequiredParameters({ username, password, email, ip });

    // Hash the password
    const passwordHashed = await bcrypt.hash(password, 12);

    // Get today's date
    const createDate = moment().format('MM/DD/YYYY');

    // Add user to database
    const [dbUser] = await db.query('insert into users(username, email, password, create_date) VALUES($1, $2, $3, $4) returning id', [username, email, passwordHashed, createDate], 'create new user');

    // If could not register a user then throw an error
    if (!dbUser || !dbUser.id) throw { code: 500, message: 'Could not register user' };

    createdUserId = dbUser.id;

    await addUserIP(dbUser.id, ip);

    // Create a pin
    const newPin = randomstring.generate(12);

    // Hash the pin
    // const pinHashed = await bcrypt.hash(newPin, 12);

    // Add a verification code in the database for a new user registration
    await addUserVerificationCode(dbUser.id, newPin, 'new user');

    // Send email with the pin
    const subject = 'Your Verification Code is Here';
    const body = `Your verification code is: ${newPin}, click on the link to activate your account http://localhost:3030/users/${dbUser.id}/verifyRegistration/${newPin}`;

    return await sendEmailText(email, subject, body);
  } catch (error) {
    if (createdUserId) db.query('delete from users where id=$1', [createdUserId], 'delete user due to error in verification');
    srcFileErrorHandler(error, 'Could not register user and generate user pin');
  }
};

/**
 * @function verifyRegistrationCode
 * @summary Verify user registration via user id and verification code
 * @param {*} req http request contains user information
 * @returns {object} verifyRegistrationResults
 * @throws {object} errorCodeAndMsg
 */
const verifyRegistrationCode = async function verifyRegistrationCode(req) {
  try {
    const {
      userId,
      verificationCode
    } = req.params;

    await checkRequiredParameters({ userId, verificationCode });

    // Get user verification code from database
    const dbUserCode = await verifyUserVerificationCode(userId, verificationCode, 'new user');

    // If could not update a user then throw an error
    if (!dbUserCode || !dbUserCode.user_id || dbUserCode.user_id != userId) throw { code: 500, message: 'Could not verify user registration' };

    // Update user in database
    const [dbUser] = await db.query("update users set status='verified' where id=$1 and status='created' returning id", [userId], 'update user status after verification');

    if (dbUser?.id != userId) throw { code: 500, message: 'Could not update user status after verification' };

    // Delete user verification code from database
    deleteUserVerificationCode(dbUserCode.user_id, verificationCode, 'new user');

    return { results: 'User verified successfully!' };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not verify and update user');
  }
};

/**
 * @function login
 * @summary Login to the system
 * @param {*} req http request contains email, password, and ip
 * @returns {object} credientials Access Token and Refresh Token
 * @throws {object} errorCodeAndMsg
 */
const login = async function login(req) {
  try {
    // Extract email, password, and ip
    const { email, password, ip } = req.body;

    // Check if there is no email or pin
    await checkRequiredParameters({ email, password, ip });

    // Get user information from database and check if it matches
    const userDb = await getUserByEmail(email);

    if (userDb && userDb.email == email && password && password !== 'null' && userDb.password !== 'null' && await bcrypt.compare(password, userDb.password)) {
      // Generate access token and refresh token
      const userSign = {
        id: userDb.id,
        username: userDb.username,
        firstName: userDb.firstname,
        lastName: userDb.lastname,
        avatarUrl: userDb.avatar_url
      };

      const accessToken = await jwt.sign(userSign, accessTokenSecret, { expiresIn: '30m' });
      const refreshToken = await jwt.sign(userSign, refreshTokenSecret);

      // Get today's date
      const loginDate = moment().format('MM/DD/YYYY');

      // Update the database with the new refresh token
      await db.query('update users set refresh_token=$1, login_date=$2 where email=$3', [refreshToken, loginDate, email], 'Set user refresh token');

      // Update user ip
      await addUserIP(userDb.id, ip);

      // Return the access token and the refresh token
      return ({ accessToken, refreshToken });
    } else throw { code: 401, message: 'Please check email and password' };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not login');
  }
};

/**
 * @function logout
 * @summary Logout of the system by an access toke and a refresh token
 * @param {*} req http request contains access token and refresh token
 * @returns {object} logoutMsg
 * @throws {object} errorCodeAndMsg
 */
const logout = async function logout(req) {
  try {
    // Extract token and refresh token
    const { token } = req.headers;
    const refreshToken = req.cookies['refresh_token'];

    await checkRequiredParameters({ token, refreshToken });

    // Verify both tokens
    const tokenVerify = await jwt.verify(token, accessTokenSecret);
    const refreshTokenVerify = await jwt.verify(refreshToken, refreshTokenSecret);

    if (tokenVerify.id != refreshTokenVerify.id) throw { code: 401, message: 'Please provide valid token and refresh token' };

    // Delete refresh token from database
    const [dbResults] = await db.query("update users set refresh_token='' where refresh_token=$1 and id=$2 returning id", [refreshToken, refreshTokenVerify.id], 'logout user');

    if (dbResults) {
      return ({ 'results': 'Logged out successful' });
    } else {
      throw { code: 500, message: 'Could not delete token' };
    }
  } catch (error) {
    srcFileErrorHandler(error, 'Could not logout');
  }
};

/**
 * @function logoutByCookie
 * @summary Logout of the system by cookie
 * @param {*} req http request contains refresh token
 * @returns {object} logoutMsg
 * @throws {object} errorCodeAndMsg
 */
const logoutByCookie = async function logoutByCookie(req) {
  try {
    // Extract refresh token from cookie
    const refreshToken = req.cookies['refresh_token'];

    await checkRequiredParameters({ refreshToken });

    // Verify refresh token
    const refreshTokenVerify = await jwt.verify(refreshToken, refreshTokenSecret);

    // Delete refresh token from database
    const [dbResults] = await db.query("update users set refresh_token='' where refresh_token=$1 and id=$2 returning id", [refreshToken, refreshTokenVerify.id], 'logout user by cookie');

    if (dbResults) {
      return ({ 'results': 'Logged out successful' });
    } else {
      throw { code: 500, message: 'Could not delete token' };
    }
  } catch (error) {
    srcFileErrorHandler(error, 'Could not logout by cookie');
  }
};

/**
 * @function renewToken
 * @summary Get new token from refresh token
 * @param {*} req http request contains access token and refresh token
 * @returns {object} credentials new access token and new refresh token
 * @throws {object} errorCodeAndMsg
 */
const renewToken = async function renewToken(req) {
  try {
    // Extract token and refresh token
    const { token } = req.headers;
    const { refreshToken } = req.body;

    await checkRequiredParameters({ token, refreshToken });

    // Verify both tokens
    const tokenVerify = await jwt.verify(token, accessTokenSecret);
    const refreshTokenVerify = await jwt.verify(refreshToken, refreshTokenSecret);

    // Check the email on both of the tokens
    if (tokenVerify.id === refreshTokenVerify.id && tokenVerify.username === refreshTokenVerify.username) {
      // Check if this refresh token still active in the database
      const [queryResults] = await db.query('select id, username, refresh_token from users where refresh_token=$1 and id=$2', [refreshToken, tokenVerify.id], 'get refresh token');
      if (queryResults?.id === tokenVerify.id && queryResults?.username === tokenVerify.username) {
        // Generate a new access token
        const userSign = { id: tokenVerify.id, username: tokenVerify.username, firstName: tokenVerify.firstName, lastName: tokenVerify.lastName, avatarUrl: tokenVerify.avatarUrl };
        const newAccessToken = await jwt.sign(userSign, accessTokenSecret, { expiresIn: '30m' });

        // Generate a new refresh token
        const newRefreshToken = await jwt.sign(userSign, refreshTokenSecret);
        // Update the database with the new refresh token
        await db.query('update users set refresh_token=$1 where id=$2', [newRefreshToken, userSign.id]);

        // Return new access token and same refresh token
        return ({ 'accessToken': newAccessToken, 'refreshToken': newRefreshToken });
      } else {
        const dbMsg = 'Could not query and verify user';
        logger.error({ dbMsg, queryResults });
        throw { code: 401, message: dbMsg };
      }
    } else {
      throw { code: 401, message: 'Could not verify tokens' };
    }
  } catch (error) {
    srcFileErrorHandler(error, 'Could not generate a new token from existing refresh token');
  }
};

/**
 * @function renewTokenByCookie
 * @summary Get new token from refresh token cookie
 * @param {*} req http request contains access token and refresh token
 * @returns {object} credentials new access token and new refresh token
 * @throws {object} errorCodeAndMsg
 */
const renewTokenByCookie = async function renewTokenByCookie(req) {
  try {
    // Extract refresh token from cookie
    const refreshToken = req.cookies['refresh_token'];

    await checkRequiredParameters({ refreshToken });

    // Verify refresh token
    const refreshTokenVerify = await jwt.verify(refreshToken, refreshTokenSecret);

    // Check if this refresh token still active in the database
    const [queryResults] = await db.query('select id, username, refresh_token from users where refresh_token=$1 and id=$2', [refreshToken, refreshTokenVerify.id]);

    if (queryResults?.refresh_token === refreshToken && queryResults?.id === refreshTokenVerify.id && queryResults?.username === refreshTokenVerify.username) {
      const userSign = { id: refreshTokenVerify.id, username: refreshTokenVerify.username, firstName: refreshTokenVerify.firstName, lastName: refreshTokenVerify.lastName, avatarUrl: refreshTokenVerify.avatarUrl };

      // Generate a new access token
      const newAccessToken = await jwt.sign(userSign, accessTokenSecret, { expiresIn: '30m' });

      // Generate a new refresh token
      const newRefreshToken = await jwt.sign(userSign, refreshTokenSecret);

      // Update the database with the new refresh token
      await db.query('update users set refresh_token=$1 where id=$2', [newRefreshToken, userSign.id]);

      // Return new access token and same refresh token
      return ({ 'accessToken': newAccessToken, 'refreshToken': newRefreshToken });
    } else {
      const dbMsg = 'Could not verify user token';
      logger.error({ dbMsg, queryResults });
      throw { code: 401, message: dbMsg };
    }
  } catch (error) {
    srcFileErrorHandler(error, 'Could not generate a new token from existing refresh token by cookie');
  }
};

/**
 * @function verifyToken
 * @summary Verify token and return user information
 * @param {object} req http request contains access token
 * @returns {object} user information from token
 * @throws {string} errorMsg
 */
const verifyToken = async function verifyToken(req) {
  try {
    const { token } = req.headers;

    console.log(token);

    await checkRequiredParameters({ token });

    const results = await jwt.verify(token, accessTokenSecret);

    if (!results) {
      throw { code: 401, messages: 'Access denied' };
    }

    return ({ id: results.id, username: results.username, firstName: results.firstName, lastName: results.lastName, avatarUrl: results.avatarUrl });
  } catch (error) {
    srcFileErrorHandler(error, 'Could not verify token');
  }
};

/**
 * @function getTokenUser
 * @summary Get user information from token
 * @param {object} user User information
 * @returns {object} User information
 * @throws {object} errorCodeAndMsg
 */
const getTokenUser = async function getTokenUser(user) {
  try {
    if (user) {
      return {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        avatarUrl: user.avatarUrl
      };
    } else {
      throw {
        code: 404,
        message: 'Could not find user information'
      };
    }
  } catch (error) {
    srcFileErrorHandler(error, 'Could not get user information');
  }
};

/**
 * @function requestPasswordReset
 * @summary Check if username and email in the database and send a verification code
 * @param {*} req http request contains access token and refresh token
 * @returns {object} requestResults
 * @throws {object} errorCodeAndMsg
 */
const requestPasswordReset = async function requestPasswordReset(req) {
  try {
    const { username, email } = req.body;

    console.log(username, email);

    await checkRequiredParameters({ username, email });

    const [dbUser] = await db.query('select id, username, email from users where username=$1 and email=$2', [username, email], 'check existing username and email for password reset');

    if (dbUser?.username === username && dbUser?.email === email) {
      // Create a pin
      const newPin = randomstring.generate(12);

      // Update verification code in the database
      await addUserVerificationCode(dbUser.id, newPin, 'password reset');

      // Send email with the pin
      const subject = 'Reset Password Request - Your Verification Code is Here';
      const body = `To continue with your reset password request click on the link: http://localhost:3030/users/${dbUser.id}/verifyPasswordReset/${newPin}`;

      return await sendEmailText(email, subject, body);
    } else if (!dbUser) {
      throw {
        code: 404,
        message: 'Could not find user information'
      };
    }
  } catch (error) {
    srcFileErrorHandler(error, 'Could not request password reset');
  }
};

module.exports = {
  registerUser,
  verifyRegistrationCode,
  login,
  logout,
  logoutByCookie,
  renewToken,
  renewTokenByCookie,
  verifyToken,
  getTokenUser,
  requestPasswordReset
};
