const express = require('express');
const multer = require('multer');
const router = express.Router();
const UserController = require('../controllers/userController');
const auth = require('../middleware/auth');
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
router.post('/verify-otp', UserController.verifyOtp);
router.post('/delete-account', UserController.deleteAccount);

module.exports = router;