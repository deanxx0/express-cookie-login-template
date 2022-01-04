var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const helmet = require('helmet');
const cors = require('cors');
const https = require('https');
const fs = require('fs');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(helmet());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/index', indexRouter);
app.use('/users', usersRouter);

const httpsOptions = {
  key: fs.readFileSync('./cert/private.key'),
  cert: fs.readFileSync('./cert/private.crt')
};
https.createServer(httpsOptions, app).listen(3001);

module.exports = app;
