const express = require('express');
const router = express.Router();
const profileSrc = require('../src/profileSrc');
const { callSrcFile, callSrcFileSkipVerify } = require('../utils/srcFileAuthorization');

/**
 * @summary Delete a user
 */
router.delete('/users', async (req, res) => {
  callSrcFile(profileSrc, 'deleteUser', [req], req, res);
});

/**
 * @summary Update user's account information
 */
router.patch('/users', async (req, res) => {
  const { username, email, firstName, lastName, mobile } = req.body;
  callSrcFile(profileSrc, 'updateUserInformation', [username, email, firstName, lastName, mobile], req, res);
});

/**
 * @summary Get user's profile picture url
 */
router.get('/users/avatar', async (req, res) => {
  callSrcFile(profileSrc, 'getUserAvatar', [], req, res);
});

/**
 * @summary Update user's profile picture
 */
router.patch('/users/avatar', async (req, res) => {
  callSrcFile(profileSrc, 'updateUserAvatar', [req], req, res);
});

module.exports = router;
