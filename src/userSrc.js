const jwt = require('jsonwebtoken');
const randomstring = require('randomstring');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { logger } = require('../utils/logger');
const { checkRequiredParameters, srcFileErrorHandler } = require('../utils/srcFile');
const { sendEmailText } = require('../utils/email');
const db = require('../utils/db');
const { addUserVerificationCode, verifyUserVerificationCode, deleteUserVerificationCode } = require('./userVerificationSrc');

/**
 * @function getUserById
 * @summary Get user from database
 * @param {string} userId User's id
 * @returns {object} getUserByIdResults
 * @throws {boolean} false
 */
const getUserById = async function getUserById(userId, status = 'verified') {
  // Check if there is no userId
  if (!userId) throw { code: 400, message: 'Please provide a user id' };

  const [dbUser] = await db.query('select * from users where id=$1 and status=$2', [userId, status], 'Get user from db by id');

  return (dbUser ? dbUser : false);
};

/**
 * @function getUserByEmail
 * @summary Get user from database
 * @param {string} email User's email
 * @returns {object} getUserByEmailResults
 * @throws {boolean} false
 */
const getUserByEmail = async function getUserByEmail(email, status = 'verified') {
  // Check if there is no email
  if (!email) throw { code: 400, message: 'Please provide a user email' };

  const [dbUser] = await db.query('select * from users where email=$1 and status=$2', [email, status], 'Get user from db by email');

  return (dbUser ? dbUser : false);
};

/**
 * @function getUserByUsername
 * @summary Get user from database by username
 * @param {string} username User's username
 * @returns {object} getUserByUsernameResults
 * @throws {boolean} false
 */
const getUserByUsername = async function getUserByUsername(username, status = 'verified') {
  // Check if there is no username
  if (!username) throw { code: 400, message: 'Please provide a username' };

  const [dbUser] = await db.query('select * from users where username=$1 and status=$2', [username, status], 'Get user from db by username');

  return (dbUser ? dbUser : false);
};

/**
 * @function checkUsernameAvailablity
 * @summary Check if username already in the database
 * @param {*} req http request contains access token and refresh token
 * @returns {object} checkUsernameResults
 * @throws {object} errorCodeAndMsg
 */
const checkUsernameAvailablity = async function checkUsernameAvailablity(req) {
  try {
    const { username } = req.body;

    await checkRequiredParameters({ username });

    const [dbUser] = await db.query('select username from users where username=$1', [username], 'check existing username');

    return { username: dbUser?.username || false };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not check for existing username');
  }
};

module.exports = {
  getUserById,
  getUserByEmail,
  getUserByUsername,
  checkUsernameAvailablity
};
