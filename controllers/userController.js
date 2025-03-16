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
            logger.warn(`Registration failed: Email ${email} already exists`);
            return res.status(400).json({ success: false, message: 'Email already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        
        // Create new user
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            companyName,
            age,
            dob,
            image,
            isVerified: false,
            verificationToken
        });

        await newUser.save();
        
        // Send verification email
        await sendVerificationEmail(email, verificationToken);
        
        logger.info(`User registered successfully: ${email}`);
        res.status(201).json({ 
            success: true, 
            message: 'Registration successful! Please check your email to verify your account.',
            redirect: '/verification-sent'
        });
    } catch (error) {
        logger.error('Registration failed:', error);
        res.status(500).json({ success: false, message: 'Registration failed', error });
    }
};

exports.verifyEmail = async (req, res) => {
    const { token } = req.params;
    
    try {
        // Find user with the verification token
        const user = await User.findOne({ verificationToken: token });
        
        if (!user) {
            logger.warn(`Email verification failed: Invalid token ${token}`);
            return res.status(400).json({ success: false, message: 'Invalid verification token' });
        }
        
        // Update user verification status
        user.isVerified = true;
        user.verificationToken = undefined; // Clear the token
        await user.save();
        
        logger.info(`Email verified successfully for ${user.email}`);
        
        // Redirect to frontend verification success page
        res.redirect(`${process.env.FRONTEND_URL}/verification-success`);
    } catch (error) {
        logger.error('Email verification failed:', error);
        res.status(500).json({ success: false, message: 'Email verification failed', error });
    }
};

// Helper function to send verification email
const sendVerificationEmail = async (email, token) => {
    const verificationUrl = `${process.env.API_URL}/users/verify-email/${token}`;
    
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
        subject: 'Verify Your Email Address',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4a90e2;">Verify Your Email Address</h2>
                <p>Thank you for registering! Please click the button below to verify your email address:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${verificationUrl}" style="background-color: #4a90e2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                        Verify Email
                    </a>
                </div>
                <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
                <p>This link will expire in 24 hours.</p>
            </div>
        `,
    };

    try {
        await transporter.sendMail(mailOptions);
        logger.info(`Verification email sent to ${email}`);
    } catch (error) {
        logger.error('Error sending verification email:', error);
        throw new Error('Failed to send verification email');
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

        // Check if email is verified
        if (!user.isVerified) {
            logger.warn(`Login failed: Email not verified for ${email}`);
            return res.status(400).json({ 
                success: false, 
                message: 'Please verify your email before logging in',
                needsVerification: true
            });
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
    
    try {
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'User not found' });
        }
        
        logger.info(`Verifying OTP for ${email}: received OTP ${otp}, stored OTP ${user.otp}`);
        
        if (user.otp !== otp) {
            logger.warn(`OTP verification failed: Invalid OTP for email ${email}`);
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }
        
        // Clear OTP after successful verification
        user.otp = undefined;
        await user.save();
        
        logger.info(`OTP verified successfully for ${email}`);
        
        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
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
    try {
        const userId = req.user.id;
        
        // Find the user
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Delete user's image if it exists
        if (user.image) {
            const imagePath = path.join(__dirname, '..', user.image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        
        // Delete the user
        await User.findByIdAndDelete(userId);
        
        logger.info(`User account deleted: ${user.email}`);
        res.status(200).json({ success: true, message: 'Account deleted successfully' });
    } catch (error) {
        logger.error('Account deletion failed:', error);
        res.status(500).json({ success: false, message: 'Failed to delete account', error });
    }
};

// Add a route to resend verification email
exports.resendVerification = async (req, res) => {
    const { email } = req.body;
    
    try {
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'User not found' });
        }
        
        if (user.isVerified) {
            return res.status(400).json({ success: false, message: 'Email is already verified' });
        }
        
        // Generate new verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        user.verificationToken = verificationToken;
        await user.save();
        
        // Send verification email
        await sendVerificationEmail(email, verificationToken);
        
        res.status(200).json({ 
            success: true, 
            message: 'Verification email has been resent'
        });
    } catch (error) {
        logger.error('Failed to resend verification email:', error);
        res.status(500).json({ success: false, message: 'Failed to resend verification email', error });
    }
};