const express = require('express');
const multer = require('multer');
const router = express.Router();
const UserController = require('../controllers/userController');
const path = require('path');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});

const upload = multer({ storage });

router.post('/register', upload.single('image'), UserController.register);
router.post('/login', UserController.login);
router.post('/delete', UserController.deleteAccount);
router.post('/verify-otp', UserController.verifyOtp);
router.delete('/delete-account', UserController.deleteAccount);
router.get('/verify-email/:token', UserController.verifyEmail);
router.post('/resend-verification', UserController.resendVerification);

module.exports = router;