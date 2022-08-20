const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const con = require('./../db_connection.js');
const sendEmail = require('./../email');

const signToken = (id) => {
  return jwt.sign({ id: id }, process.env.SECRET, {
    expiresIn: '1d',
  });
};

const refreshTokenFun = (id) => {
  return jwt.sign({ id }, process.env.REFRESHTOKEN, {
    expiresIn: '1d',
  });
};

const comparePassword = async (enteredPassword, savedPassword, savedSalt) => {
  const hashedPassword = await bcrypt.hash(enteredPassword, savedSalt);
  if (savedPassword !== hashedPassword) return true;
  return false;
};

exports.refreshToken = (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token)
      return res.status(400).json({
        status: 'fail',
        message: 'You are not logged in. Please login again.',
      });

    // TOKEN Verification
    jwtPayload = jwt.verify(token, process.env.REFRESHTOKEN);

    res.cookie('accessToken', signToken(jwtPayload.id), {
      httpOnly: true,
    });
    res.cookie('refreshToken', refreshTokenFun(jwtPayload.id), {
      httpOnly: true,
    });

    return res.status(200).json({
      status: 'success',
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({
        status: 'fail',
        message: 'Your token has expired!. Please try logging in again.',
      });
    if (err.name === 'JsonWebTokenError')
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token! Please try logging in again.',
      });
  }
};

const getQuotesFun = async (id) => {
  return await con.query_prom(
    'SELECT Quote FROM Quotes WHERE Owner=? AND isDeleted=?',
    [id, 0]
  );
};

// Returns sugesstions in a STRING!
const strongPassword = async (password, passwordConfirm) => {
  // if the password is NOT confirmed!
  if (password !== passwordConfirm) {
    return 'Password does not match. Please try again!';
  }

  const specialChar = /[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;

  // Checking for strong password
  if (!specialChar.test(password)) {
    return 'Password must contain a special character';
  }

  if (!(password.length >= 8)) {
    return 'Password must be 8 characters long';
  }

  if (password.search(/[0-9]/) == -1) {
    return 'Password must contain 1 Numeric character';
  }

  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
    return 'Password must contain 1 UpperCase and 1 LowerCase character';
  }
};

exports.registerNewUser = async (req, res) => {
  try {
    // Getting all info from request body
    const newUser = {
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
    };

    // Retreiving email from DB
    const queryRes = await con.query_prom(
      'SELECT Email FROM users WHERE Email=?',
      [newUser.email]
    );

    if (queryRes.length) {
      const [{ Email }] = JSON.parse(JSON.stringify(queryRes));

      // Checking if provided email exists in DB
      if (Email.toLowerCase() === newUser.email.toLowerCase()) {
        return res.status(400).json({
          status: 'fail',
          message: 'This email is already registered!',
        });
      }
    }

    // *******************Call strongPassword() here************************
    const string = await strongPassword(
      newUser.password,
      newUser.passwordConfirm
    );

    if (string) {
      return res.status(400).json({
        status: 'Bad request',
        message: string,
      });
    }
    // Registering New User!
    const { insertId: id } = await con.query_prom(
      'INSERT INTO users (Name, Email) VALUES (?,?);',
      [newUser.name, newUser.email]
    );

    try {
      // setting up salt & hashed password
      const salt = await bcrypt.genSalt();
      await con.query_prom('UPDATE users SET salt=? WHERE Email=?', [
        salt,
        newUser.email,
      ]);
      const hashed = await bcrypt.hash(newUser.password, salt);
      await con.query_prom('UPDATE users SET Password=? WHERE Email=?', [
        hashed,
        newUser.email,
      ]);
    } catch (err) {
      if (err) console.log(err);
    }

    // Getting new Access & Refresh Token
    const token = signToken(id);
    const refToken = refreshTokenFun(id);

    // Sending cookies
    res.cookie('accessToken', token, {
      httpOnly: true,
    });
    res.cookie('refreshToken', refToken, {
      httpOnly: true,
    });

    // Sending response to client
    res.status(201).json({
      status: 'success',
      message: 'User created!',
    });
  } catch (err) {
    if (err) {
      return res.status(500).json({
        status: 'fail',
        error: err.message,
      });
    }
  }
};

exports.login = async (req, res) => {
  const userEmail = req.body.Email;
  const userPassword = req.body.Password;

  if (!userEmail || !userPassword) {
    return res.status(400).json({
      status: 'Bad request',
      message: 'Please provide the email and password',
    });
  }

  const resultVal = await con.query_prom(
    `SELECT Name, Email, Password, userID, salt FROM users WHERE Email ='${userEmail}'`
  );

  const [filterResults] = JSON.parse(JSON.stringify(resultVal));

  // const hashed = await bcrypt.hash(userPassword, filterResults.salt);

  // console.log(hashed);
  // console.log(filterResults.Password);

  if (
    !filterResults ||
    (await comparePassword(
      userPassword,
      filterResults.Password,
      filterResults.salt
    ))
  )
    return res.status(400).json({
      status: 'Bad request',
      message: 'Incorrect email or password',
    });

  const token = signToken(filterResults.userID);
  const refToken = refreshTokenFun(filterResults.userID);

  res.cookie('accessToken', token, {
    httpOnly: true,
  });
  res.cookie('refreshToken', refToken, {
    httpOnly: true,
  });

  res.status(200).json({
    status: 'success',
    message: 'Logged In!',
  });
};

exports.logout = (req, res) => {
  res.clearCookie('refreshToken');
  res.clearCookie('accessToken');
  return res.status(200).json({
    status: 'success',
    message: 'Logged Out!',
  });
};

// checkId function
exports.checkId = async (req, res, next) => {
  const reqId = req.params.id * 1;
  if (reqId < 1 || !Number.isInteger(reqId)) {
    return res.status(404).json({
      status: 'Bad Request',
      message: 'Invalid Id',
    });
  }
  next();
};

// Controllers
exports.getQuotes = (req, res) => {
  res.json(res.paginatedResults);
};

exports.getMyQuotes = async (req, res, next) => {
  try {
    const myQuote = await getQuotesFun(req.id);

    if (myQuote.length === 0) {
      return res.status(200).json({
        message: 'You have no quotes yet.',
      });
    }

    res.status(200).json({
      status: 'success',
      id: req.id,
      yourQuotes: myQuote,
    });
  } catch (err) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid Id. Please enter the correct Id.',
    });
  }
};

exports.getQuotesOfTheUser = async (req, res, next) => {
  try {
    const { userID: id } = req.body;
    const myQuote = await getQuotesFun(id);
    res.status(200).json({
      status: 'success',
      id,
      yourQuotes: myQuote,
    });
  } catch (err) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid Id. enter the correct Id.',
    });
  }

  next();
};

exports.postQuote = async (req, res) => {
  const data = req.body;

  const updated = await con.query_prom(
    `INSERT INTO Quotes (Quote, Author, Owner) VALUES (?,?,?)`,
    [data.Quote, data.Author, data.Owner]
  );

  res.status(201).json({
    status: 'success',
    data: {
      information: {
        updated,
      },
      message: 'Your Quote has been posted!',
    },
  });
};

exports.deleteQuotes = async (req, res) => {
  const Id = req.params.id * 1;

  const Owners = await con.query_prom(
    'SELECT Owner FROM Quotes WHERE Id=? AND isDeleted=?',
    [Id, 0]
  );
  if (!Owners)
    return res.status(404).json({
      status: 'fail',
      message: 'Owner not found',
    });
  const [owner] = Owners.map((owner) => owner.Owner);
  if (owner !== req.id) {
    return res.status(400).json({
      status: 'fail',
      message:
        'This Quote does not belong to you. Please delete the quote that you own.',
    });
  }
  const { affectedRows } = await con.query_prom(
    'UPDATE Quotes SET isDeleted=? WHERE Id=?',
    [1, Id]
  );
  res.status(200).json({
    status: 'success',
    message: 'data deleted',
    data: {
      affectedRows,
    },
  });
};

exports.protect = async (req, res, next) => {
  try {
    // if the token is provided in the cookie
    if (!req.cookies.accessToken) {
      return res.status(401).json({
        status: 'Unauthorized',
        message: 'You are not logged in! Please log in to get access.',
      });
    }
    // verify token
    const { id } = jwt.verify(req.cookies.accessToken, process.env.SECRET);
    req.id = id;
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({
        status: 'fail',
        message: 'Your token has expired!. Please try logging in again.',
      });
    if (err.name === 'JsonWebTokenError')
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid token! Please try logging in again.',
      });
  }

  next();
};

exports.forgotPassword = async (req, res, next) => {
  // 1. get user based on POSTED emails
  const resultVal = await con.query_prom(
    'SELECT Email, Password, salt FROM users WHERE Email=?',
    [req.body.Email]
  );

  const [filterResults] = JSON.parse(JSON.stringify(resultVal));

  if (!req.body.Email || !req.body.Password) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide email and password.',
    });
  }
  if (
    !filterResults ||
    (await comparePassword(
      req.body.Password,
      filterResults.Password,
      filterResults.salt
    ))
  ) {
    return res.status(400).json({
      status: 'fail',
      message: 'Incorrect email or password.',
    });
  }

  // 2. generate random reset tokens
  const [resetToken, passwordResetToken, passwordResetExpires] =
    await createResetPasswordToken(filterResults.Email);

  console.log(resetToken, passwordResetToken, passwordResetExpires);

  // 3. send it to user's email
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/resetPassword/${resetToken}`;
  const message = `Forgot your password? Send a request to with your new password and confirmPassword to:${resetURL}.\nIf you didn't forgot your password, then ignore this email`;

  try {
    await sendEmail({
      email: req.body.Email,
      subject: 'Your password reset token (valid only for 10 minutes)',
      message,
    });
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
    await con.query_prom(
      'UPDATE users SET passwordResetToken=?, passwordResetExpires=? WHERE Email=?',
      [passwordResetToken, passwordResetExpires, filterResults.Email]
    );
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      status: 'Internal server error',
      message: 'There was an error sending the email. Try again later!',
    });
  }
};

const createResetPasswordToken = async function (Email) {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  const passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

  await con.query_prom(
    'UPDATE users SET passwordResetToken=?, passwordResetExpires=? WHERE Email=?',
    [passwordResetToken, passwordResetExpires, Email]
  );

  return [resetToken, passwordResetToken, passwordResetExpires];
};

exports.resetPassword = async (req, res, next) => {
  // try {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  // 1. Getting user based on tokens

  // queryResult = [] : when (NO DATA), queryResult = [asdfasdf] : when [DATA];
  const resultVal = await con.query_prom(
    'SELECT userID, passwordResetExpires, Password, salt FROM users WHERE passwordResetToken=?',
    [hashedToken]
  );

  const [filterResults] = JSON.parse(JSON.stringify(resultVal));

  console.log(new Date());
  console.log(filterResults);
  // console.log(JSON.parse(filterResults.passwordResetExpires));

  if (!filterResults) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid or expired token. Please try again!',
    });
  }

  const hashed = await bcrypt.hash(req.body.Password, filterResults.salt);

  if (hashed === filterResults.Password) {
    return res.status(200).json({
      status: 'fail',
      message:
        'Old password matches with the new password. Please try enter a new unique password!',
    });
  }

  const string = await strongPassword(
    req.body.Password,
    req.body.PasswordConfirm
  );
  if (string) {
    return res.status(400).json({
      status: 'fail',
      message: string,
    });
  }

  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(req.body.Password, salt);
  // 1.)
  await con.query_prom(
    'UPDATE users SET Password=?, salt=?, passwordResetToken=?, passwordResetExpires=? WHERE passwordResetToken=?',
    [hashedPassword, salt, null, null, hashedToken]
  );

  // 2. If token has not expired, and user exists, then set new password
  // if (!(filterResults.passwordResetExpires.getTime() > Date.now())) {
  //   return res.status(400).json({
  //     status: 'fail',
  //     message: 'Token is invalid or expired',
  //   });
  // }

  // 3. Update changedPasswordAt property for the user
  // 4. Log in the user, send JWT token
  const jwtToken = signToken(filterResults.userID);
  res.cookie(jwtToken);
  res.status(200).json({
    status: 'success',
  });
};
