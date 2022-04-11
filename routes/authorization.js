const express = require('express');
const router = express.Router();
const authorizationSrc = require('../src/authorizationSrc');
const { callSrcFile, callSrcFileSkipVerify } = require('../utils/srcFileAuthorization');

/**
 * @summary Register a new user
 */
router.post('/users', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'registerUser', [req], req, res);
});

/**
 * @summary Verify user's registration
 */
router.get('/users/:userId/verifyRegistration/:verificationCode', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'verifyRegistrationCode', [req], req, res);
});

/**
 * @summary Login user
 */
router.post('/login', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'login', [req], req, res);
});

/**
 * @summary Logout and delete the stored refresh token by an access token and a refresh tokens
 */
router.delete('/logout', async (req, res) => {
  callSrcFile(authorizationSrc, 'logout', [req], req, res, false);
});

/**
 * @summary Logout and delete the stored refresh token by cookie
 */
router.delete('/logoutByCookie', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'logoutByCookie', [req], req, res);
});

/**
 * @summary Get a new access token using existing refresh token
 */
router.post('/renewToken', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'renewToken', [req], req, res);
});

/**
 * @summary Get a new access token using existing refresh token cookie
 */
router.post('/renewTokenByCookie', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'renewTokenByCookie', [req], req, res);
});

/**
 * @summary Check if username is in database
 */
router.post('/checkUsernameAvailablity', async (req, res) => {
  callSrcFileSkipVerify(authorizationSrc, 'checkUsernameAvailablity', [req], req, res);
});

/**
 * @summary Get user from token
 */
router.get('/getTokenUser', async (req, res) => {
  callSrcFile(authorizationSrc, 'getTokenUser', [], req, res, false);
});

module.exports = router;