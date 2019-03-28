const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');

const indexRouter = require('./routes/index');
const webAuthnRouter = require('./routes/webauthn');

const app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use('/webauthn', express.static(path.join(__dirname, 'public')));

app.use('/api/webauthn', webAuthnRouter);

module.exports = app;
