const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const authMiddleware = require('../../middleware/auth');

const User = require('../../models/User');

// @route   GET api/auth
// @desc    Test route
// @access  Protected
router.get('/', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).send('500 Server error');
  }
});

// @route  POST api/auth
// @desc   Login user
// @access Public
router.post(
  '/',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
  ],
  async (req, res) => {
    const validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
      return res
        .status(400)
        .json({ validationErrors: validationErrors.array() });
    }

    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email: email });
      if (!user) {
        return res
          .status(400)
          .json({ validationErrors: [{ msg: 'Invalid credentials' }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ validationErrors: [{ msg: 'Invalid credentials' }] });
      }

      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get('jwtSecretToken'),
        { expiresIn: 10080 },
        (err, jwtToken) => {
          if (err) throw err;
          res.json({ jwtToken });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('500 Server error');
    }
  }
);

module.exports = router;
