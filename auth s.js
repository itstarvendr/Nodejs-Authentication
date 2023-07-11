// Required dependencies
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Import routes and controllers
const authRoutes = require('./app/routes/authRoutes');
const authController = require('./app/controllers/authController');

// Create an instance of the Express app
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(express.static('app/public'));

// Register routes
app.use('/', authRoutes);

// Start the server
app.listen(3000, () => {
  console.log('Authentication server is running on http://localhost:3000');
});
