const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const { logger } = require('../utils/logger');
const { srcFileErrorHandler } = require('../utils/srcFile');

// Configure upload to local server
const storageLocalAvatar = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './public/files/avatars');
  },
  filename: function (req, file, cb) {
    cb(null, `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`);
  }
});

const uploadLocalAvatar = multer({
  storage: storageLocalAvatar,
  limits: {
    fileSize: 4 * 1024 * 1024, // no larger than 4mb
  },
  fileFilter: function (req, file, callback) {
    try {
      const ext = path.extname(file.originalname);
      if (ext !== '.png' && ext !== '.jpg' && ext !== '.jpeg' && ext !== '.gif') throw { code: 400, message: 'Unsupported file type, only photos are allowed for avatars' };
      logger.debug({ label: 'Filtered file - format okay' });
      callback(null, true);
    } catch (error) {
      const userMsg = error.message || 'Could not filter avatar photo';
      logger.error({ userMsg, error });
      callback({ code: 500, message: userMsg });
    }
  }
}).single('avatar');

/**
 * @function uploadAvatarLocally
 * @summary Upload user's profile picture to the avatars folder
 * @param {object} req Http request
 * @returns {object} uploadAvataresults
 * @throws {object} errorCodeAndMsg
 */
const uploadAvatarLocally = function uploadAvatarLocally(req) {
  return new Promise((resolve, reject) => {
    // Upload avatar
    uploadLocalAvatar(req, null, function (err) {
      if (!req.file) {
        logger.debug({ message: 'Upload avatar skipped, empty avatar' });
        resolve({ message: 'Empty avatar request', req });
      }

      if (err) {
        logger.error({ label: 'Could not upload avatar', results: err });
        reject(new Error({ code: 500, message: 'Could not upload avatar' }));
      } else {
        const fileUrl = req.file.path.replace('public/', '/');

        logger.debug({ message: 'Uploaded avatar successfully', results: fileUrl });
        resolve({ message: 'Uploaded avatar successfully', fileUrl, req });
      }
    });
  });
};

/**
 * @function deleteAvatarBLocalyUrl
 * @summary Delete user's profile picture by its url
 * @param {string} fileUrl File's url
 * @returns {object} deleteAvatarResults
 * @throws {boolean} false
 */
const deleteAvatarLocalByUrl = async function deleteAvatarLocalByUrl(fileUrl) {
  try {
    // Check if there is no file url
    if (!fileUrl) throw { code: 400, message: 'Please provide avatar file url' };

    await fs.unlinkSync(`${path.resolve(__dirname, '../public')}${fileUrl}`);

    return { message: 'Deleted avatar locally by its url successfully' };
  } catch (error) {
    srcFileErrorHandler(error, 'Could not delete avatar by its url');
  }
};

module.exports = {
  uploadAvatarLocally,
  deleteAvatarLocalByUrl
};
