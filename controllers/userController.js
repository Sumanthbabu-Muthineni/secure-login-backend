const User = require('../models/User');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const validator = require('validator');
const dns = require('dns');
const logger = require('../logger'); // Import the logger
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const isEmailValid = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
};

const doesEmailDomainExist = (email) => {
    const domain = email.split('@')[1];
    return new Promise((resolve, reject) => {
        dns.resolveMx(domain, (err, addresses) => {
            if (err || addresses.length === 0) {
                reject(false);
            } else {
                resolve(true);
            }
        });
    });
};

exports.register = async (req, res) => {
    const { name, email, password, companyName, age, dob } = req.body;
    const image = req.file ? req.file.path : null;

    // Validate input data
    if (!name || !email || !password) {
        logger.warn('Registration failed: All fields are required');
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            logger.warn(`Registration failed: Email already in use`);
            return res.status(400).json({ success: false, message: 'Email already in use' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            companyName,
            age,
            dob,
            image
        });

        await newUser.save();
        
        logger.info(`User registered successfully: ${email}`);
        
        res.status(201).json({ 
            success: true, 
            message: 'Registration successful! Please login to continue.',
            redirect: '/'
        });
    } catch (error) {
        logger.error('Registration failed:', error);
        res.status(500).json({ success: false, message: 'Registration failed', error });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            logger.warn(`Login failed: User not found for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            logger.warn(`Login failed: Invalid password for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await sendOtpEmail(user.email, otp);

        // Store or update OTP in the user document
        user.otp = otp;
        await user.save();

        logger.info(`OTP sent to ${email}`);
        res.status(200).json({ success: true, message: 'OTP sent to your email' });
    } catch (error) {
        logger.error('Login failed:', error);
        res.status(500).json({ success: false, message: 'Login failed', error });
    }
};

const sendOtpEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Error sending OTP email:', error);
    }
};

// New OTP verification endpoint
exports.verifyOtp = async (req, res) => {
    const { email, otp } = req.body;
    
    // Add validation
    if (!email || !otp) {
        logger.warn('OTP verification failed: Missing email or OTP');
        return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    }
    
    try {
        const user = await User.findOne({ email });
        
        if (!user) {
            logger.warn(`OTP verification failed: User not found for email ${email}`);
            return res.status(400).json({ success: false, message: 'User not found' });
        }
        
        // Make sure user.otp exists
        if (!user.otp) {
            logger.warn(`OTP verification failed: No OTP stored for user ${email}`);
            return res.status(400).json({ success: false, message: 'No OTP found. Please request a new one.' });
        }
        
        logger.info(`Verifying OTP for ${email}: received OTP ${otp}, stored OTP ${user.otp}`);
        
        // Trim both OTPs for comparison to avoid whitespace issues
        if (user.otp.trim() !== otp.trim()) {
            logger.warn(`OTP verification failed: Invalid OTP for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }
        
        // Clear OTP after successful verification
        user.otp = undefined;
        await user.save();
        
        logger.info(`OTP verified successfully for ${email}`);
        
        // Use a default JWT secret if environment variable is not set
        const jwtSecret = process.env.JWT_SECRET || 'fallback_jwt_secret_for_development';
        
        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, jwtSecret, { expiresIn: '1h' });
        
        // Return user data (excluding sensitive information)
        const userData = {
            name: user.name,
            email: user.email,
            companyName: user.companyName,
            age: user.age,
            dob: user.dob,
            image: user.image
        };
        
        res.status(200).json({ 
            success: true, 
            message: 'OTP verified successfully',
            user: userData,
            token
        });
    } catch (error) {
        logger.error('OTP verification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

exports.deleteAccount = async (req, res) => {
    console.log('Delete account request received:', req.body);
    
    try {
        // Get email from request body
        const { email } = req.body;
        
        console.log('Email from request:', email);
        
        if (!email) {
            logger.warn('Account deletion failed: No email provided');
            return res.status(400).json({ success: false, message: 'Email is required' });
        }
        
        // Find the user by email
        const user = await User.findOne({ email });
        
        console.log('User found:', user ? 'Yes' : 'No');
        
        if (!user) {
            logger.warn(`Account deletion failed: User not found with email ${email}`);
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Delete user's image if it exists
        if (user.image) {
            try {
                const imagePath = path.join(__dirname, '..', user.image);
                console.log('Attempting to delete image at:', imagePath);
                
                if (fs.existsSync(imagePath)) {
                    fs.unlinkSync(imagePath);
                    logger.info(`Deleted user image: ${imagePath}`);
                } else {
                    console.log('Image file not found at path:', imagePath);
                }
            } catch (err) {
                logger.error(`Error deleting user image: ${err.message}`);
                console.error('Image deletion error:', err);
                // Continue with account deletion even if image deletion fails
            }
        }
        
        // Delete the user
        const deleteResult = await User.findByIdAndDelete(user._id);
        console.log('Delete result:', deleteResult ? 'Success' : 'Failed');
        
        logger.info(`User account deleted: ${email}`);
        res.status(200).json({ success: true, message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Full error object:', error);
        logger.error('Account deletion failed:', error);
        res.status(500).json({ success: false, message: 'Failed to delete account', error: error.message });
    }
};