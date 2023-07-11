const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Secret key for JWT (replace this with a securely stored secret in a production system)
const secretKey = 'your-secret-key';

// Registration controller
exports.register = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user object
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // Save the user to the database
    await newUser.save();

    // Respond with success message
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Login controller
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ username });

    // Check if the user exists
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare the provided password with the stored password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // Check if the password is valid
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user._id, username: user.username }, secretKey, {
      expiresIn: '1h',
    });

    // Respond with the token
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Protected controller
exports.protected = (req, res) => {
  try {
    const token = req.headers.authorization;

    // Verify the token
    jwt.verify(token, secretKey, (error, decoded) => {
      if (error) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Respond with a success message and decoded user information
      res.status(200).json({ message: 'Authenticated', user: decoded });
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};
