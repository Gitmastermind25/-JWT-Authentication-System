// Import required libraries
const express = require('express');         // Express.js to create server and routes
const jwt = require('jsonwebtoken');       // JWT library to generate and verify tokens
const bodyParser = require('body-parser'); // Middleware to parse JSON request bodies
const cookieParser = require('cookie-parser'); // Middleware to parse cookies sent by client
const bcrypt = require('bcryptjs');            // Library to securely hash and compare passwords
const users = require('./users');              // Our mock database of users
const auth = require('./middleware/auth');     // Middleware to protect routes using access token

// Create an Express application
const app = express();

// Middleware setup
app.use(bodyParser.json());  // Parses JSON bodies for incoming requests
app.use(cookieParser());     // Parses cookies for incoming requests

// Secret keys for JWT
const ACCESS_SECRET = 'access_secret_key';  // Used to sign access tokens
const REFRESH_SECRET = 'refresh_secret_key'; // Used to sign refresh tokens

// Function to generate access token
// Access tokens are short-lived (1 minutes here) and used to access protected routes
const generateAccessToken = (user) =>
    jwt.sign({ id: user.id, username: user.username }, ACCESS_SECRET,{ expiresIn: '1m'});

// Function to generate refresh token
// Refresh tokens are long-lived (7 days here) and used to get new access tokens
const generateRefreshToken = (user) =>
    jwt.sign({ id: user.id}, REFRESH_SECRET, { expiresIn: '7d'});



// ==================== ROUTES ====================


// LOGIN route
// Client sends username and password to get access and refresh tokens
app.post('/login', (req, res)=>{
    const{ username, password} = req.body;
    const user = users.find(u => u.username === username);

    // If user doesn't exist or password is wrong, return 401 Unauthorized
    if(!user || !bcrypt.compareSync(password, user.password)){
        return res.status(401).json({message: 'Invalid credentials'});
    }

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);


    // Store refresh token with user (so server knows which token is valid)
    user.refreshToken = refreshToken;
    // Set refresh token as HTTP-only cookie
    // httpOnly: true → cannot be accessed by client-side JavaScript (good for security)
    // secure: false → for testing on HTTP (should be true in production HTTPS)
    // sameSite: 'strict' → prevents cross-site requests sending the cookie
    // maxAge → cookie expiration in milliseconds
    res.cookie('refreshToken', refreshToken, {
       httpOnly: true,
       secure: false,
       sameSite: 'strict',
       maxAge: 7 * 24 * 60 * 60 *1000,  
    });

    // Send access token in response body
    res.json({ accessToken });
});


// DASHBOARD route (protected)
// Uses 'auth' middleware to check for a valid access token
app.get('/dashboard', auth,(req, res) => {
    // req.user is set in auth middleware after verifying access token
    res.json({ message: `Welcome, ${req.user.username}`});
});


// REFRESH token route
// Client sends refresh token (via cookie) to get a new access token
app.post('/refresh',(req, res)=>{
    const token = req.cookies.refreshToken;  // Get refresh token from cookie
    if(!token) return res.status(401).json({ message: 'No refresh token provided'});

    const user = users.find(u => u.refreshToken === token);  // Check if token exists in server
    if(!user) return res.status(403).json({ message: 'Invalid refresh token'});

    try{
        jwt.verify(token, REFRESH_SECRET);  // Verify refresh token
        const accessToken = generateAccessToken(user);  // Generate new access token
        res.json({ accessToken });
    }catch(err){
        res.status(403).json({ message: 'Refresh Token expired or invalid'});
    }
});


// LOGOUT route
// Clears refresh token from server and client cookie
app.post('/logout',(req, res) =>{
    const token = req.cookies.refreshToken;  // Get refresh token from cookie
    const user = users.find(u => u.refreshToken === token); // Find user with that token
    if(user) user.refreshToken = null;     // Remove token from server

    res.clearCookie('refreshToken');  // Remove cookie from client
    res.json({ message: 'Logged out'});
});

// Start server on port 3000
app.listen(3000, () => console.log('Running on https://localhost:3000'));