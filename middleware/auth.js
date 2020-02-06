const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = (req, res, next) => {
  const jwtToken = req.header('x-auth-token');

  if (!jwtToken) {
    return res.status(401).json({ msg: 'No jwt token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(jwtToken, config.get('jwtSecretToken'));
    req.user = decoded.user;
    next();
  } catch (err) {
    return res
      .status(401)
      .json({ msg: 'Token is not valid, authorization denied' });
  }
};
