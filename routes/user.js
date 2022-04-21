const express = require('express');
const router = express.Router();
const userSrc = require('../src/userSrc');
const { callSrcFile, callSrcFileSkipVerify } = require('../utils/srcFileAuthorization');

/**
 * @summary Check if username is in database
 */
router.post('/checkUsernameAvailablity', async (req, res) => {
  callSrcFileSkipVerify(userSrc, 'checkUsernameAvailablity', [req], req, res);
});

module.exports = router;
