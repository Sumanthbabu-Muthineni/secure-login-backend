const jwt = require('jsonwebtoken');
const logger = require('../logger');

module.exports = (req, res, next) => {
    // Get token from header
    const token = req.header('x-auth-token');

    // Check if no token
    if (!token) {
        logger.warn('Authentication failed: No token provided');
        return res.status(401).json({ success: false, message: 'No token, authorization denied' });
    }

    try {
        // Use a default JWT secret if environment variable is not set
        const jwtSecret = process.env.JWT_SECRET || 'fallback_jwt_secret_for_development';
        
        // Verify token
        const decoded = jwt.verify(token, jwtSecret);
        
        // Add user from payload
        req.user = decoded;
        next();
    } catch (err) {
        logger.error('Authentication failed: Invalid token', err);
        res.status(401).json({ success: false, message: 'Token is not valid' });
    }
}; 