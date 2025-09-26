const jwt = require('jsonwebtoken'); // JWT library to verify tokens
const ACCESS_SECRET = 'access_secret_key'; // Secret key to verify access tokens

// Middleware function to protect routes
// This function checks if a valid access token is present in the request
module.exports = function(req, res, next){

    // Get the Authorization header from the request
    // It should have the format: "Bearer <accessToken>"
    const authHeader = req.headers.authorization;

    // Extract the token from the header
    // The "?" ensures it doesn’t throw an error if authHeader is undefined
    const token = authHeader?.split(' ')[1];

    // If token is missing, return 401 Unauthorized
    if(!token) return res.status(401).json({message: 'Acess token missing'});
    
    try{
        // Verify the token using the secret key
        // If valid, jwt.verify returns the payload we signed earlier (id and username)
        const decoded = jwt.verify(token, ACCESS_SECRET);

        // Attach the decoded user info to the request object
        // Now, protected routes can access req.user to know who is logged in
        req.user = decoded;

        // Call next() to allow the request to continue to the route handler
        next();
    }catch(err){
        // If token is invalid or expired, return 403 Forbidden
        return res.status(403).json({ message: 'Acesstoken expired or invalid'});
    }
};