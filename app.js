require('dotenv').config();

// Require
const express = require('express');
const methodOverride = require('method-override');
const expressSanitizer = require('express-sanitizer');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const cors = require('cors');
const requestIp = require('request-ip');
const cookieParser = require('cookie-parser');
const { logger } = require('./logger/logger');

// Require routes
const main = require('./routes/main.js');

// Application Setup
const app = express();
const serverPort = 3030;
const serverUrl = 'localhost';

// App Configurations
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({
  extended: true
}));
app.use(expressSanitizer());
app.use(methodOverride('_method'));
app.use(express.json());
app.use(requestIp.mw());
app.use(cookieParser());

// Multer Configurations to upload file
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads');
  },
  filename: function (req, file, cb) {
    cb(null, 'file.txt');
  }
});

const upload = multer({
  storage: storage,
  fileFilter: function (req, file, callback) {
    const ext = path.extname(file.originalname);
    if (ext !== '.txt') {
      return callback(new Error('Only text files are allowed'));
    }
    callback(null, true);
  }
}).single('txtFile');

// Routes

// Index Route
app.get('/', async function (req, res) {
  res.render('index');
});

// Upload a new file
app.post('/uploadFile', function (req, res) {
  upload(req, res, function (err) {
    if (err) {
      const errMsg = `Could not upload text file ${JSON.stringify(err)} ${err}`;
      logger.error(errMsg);
      res.send(errMsg);
    } else {
      logger.debug('File uploaded successfully!');
      res.send('File uploaded successfully!');
    }
  });
});

// Not Found Route
app.get('*', function (req, res) {
  res.render('notFound');
});

// Start server on specified url and port
app.listen(serverPort, serverUrl, function () {
  logger.info('Application started successfully...');
  logger.info(`Server can be accessed on http://${serverUrl}:${serverPort}`);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error(reason);
  logger.error(promise);
});

process.on('uncaughtException', (reason) => {
  logger.error(reason);
});
