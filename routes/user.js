const express = require('express');
const router = express.Router();
const userSrc = require('../src/userSrc');
const { callSrcFile, callSrcFileSkipVerify } = require('../utils/srcFileAuthorization');

/**
 * @summary Check if username is in database
 */
router.get('/user/:username/usernameAvailablity', async (req, res) => {
  const { username } = req.params;

  callSrcFileSkipVerify(userSrc, 'isUsernameAvailable', [username], req, res);
});

module.exports = router;
