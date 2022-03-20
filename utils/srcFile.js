const { logger } = require('./logger');
const { isHttpCode } = require('./httpTools');
// const authorizationSrc = require('../src/authorizationSrc');

/**
 * @function callSrcFile
 * @description Custom function to call src file after verifying user token
 * @param {string} srcFunctionName - source file function name
 * @param {array} parameters - Variables to send with the function
 * @returns {object} response
 */
const callSrcFile = async function callSrc(srcFile, functionName, parameters, req, res) {
  let userCheckPass = false;
  try {
    let user = {};
    user = 'remove this line when authorization logic is added';
    // user = await authorizationSrc.verifyToken(req);

    if (user) userCheckPass = true;
    else throw new Error('Not authorized');

    const data = await srcFile[functionName].apply(this, [...parameters, user]);
    res.status(200).json({
      data
    });
  } catch (error) {
    logger.error(error);
    if (error && error.code) {
      res.status(error.code).json({
        error
      });
    } else if (error && !userCheckPass) {
      res.status(401).json({
        error: {
          code: 401,
          message: 'Not authorized'
        }
      });
    } else {
      res.status(500).json({
        error: {
          code: 500,
          message: `Could not process ${req.originalUrl} request`
        }
      });
    }
  }
};

/**
 * @function callSrcFileSkipVerify
 * @description Custom function to call src file and skiping user token verification
 * @param {object} srcFile - Source file to call a function on
 * @param {string} srcFunctionName - source file function name
 * @param {array} parameters - Variables to send with the function
 * @param {*} req - Http request
 * @param {*} res - Http response
 * @returns {object} response
 */
const callSrcFileSkipVerify = async function callSrcFileSkipVerify(srcFile, functionName, parameters, req, res) {
  try {
    const data = await srcFile[functionName].apply(this, [...parameters]);
    res.status(200).json({
      data
    });
  } catch (error) {
    logger.error(error);
    if (error && error.code) {
      res.status(error.code).json({
        error
      });
    } else {
      res.status(500).json({
        error: {
          code: 500,
          message: `Could not process ${req.originalUrl} request`
        }
      });
    }
  }
};

/**
 * @function srcFileErrorHandler
 * @description Check if the error has an http code, a message, then handle throwing error with code
 * @param {*} error - Error to handle
 * @param {string} responseMessage - Error message to return on response
 * @param {number} responseCode - Http code to send on response
 * @throws errorWithCode
 */
const srcFileErrorHandler = async function srcFileErrorHandler(error, responseMessage, responseCode = 500) {
  if (error.code && isHttpCode(error.code)) {
    logger.error(error);
    throw error;
  }
  logger.error({ responseMessage, error });
  throw { code: responseCode, message: responseMessage };
};

module.exports = {
  callSrcFile,
  callSrcFileSkipVerify,
  srcFileErrorHandler
};
