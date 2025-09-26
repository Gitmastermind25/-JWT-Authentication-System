const bcrypt = require('bcryptjs'); // Library to securely hash passwords

// Mock database of users
// In a real application, you would store users in a real database
const user = [
    {
        id: 1, // Unique identifier for the user
        username: "Yogita",
        // Password is hashed using bcrypt for security
        // bcrypt.hashSync(password, saltRounds) returns a hashed password
        // saltRounds (8 here) adds complexity to prevent brute-force attacks
        password: bcrypt.hashSync("password123", 8),
        refreshToken: null      // Placeholder to store refresh token when user logs in
    }
];

// Export the user array so it can be used in other files (like index.js)
module.exports = user;