# Server Setup Guide

1. **Clone the repository**
   ```bash
   git clone https://github.com/Sumanthbabu-Muthineni/secure-login-backend
   cd secure-login-backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Create environment variables**
   Create a `.env` file in the server directory with the following variables:
   ```
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/secure-login-system
   JWT_SECRET=your_jwt_secret_key
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_email_app_password
   ```


4. **Start the server**
   ```bash
   node server.js
   ```
   The server will start running on http://localhost:5000

## Features
- User registration with profile image upload
- Secure login with email/password
- Two-factor authentication with email OTP
- JWT token-based authentication
- User profile management
- Account deletion functionality

## API Endpoints

### User Routes
- `POST /api/users/register` - Register a new user
- `POST /api/users/login` - Login with email and password
- `POST /api/users/verify-otp` - Verify OTP for two-factor authentication
- `POST /api/users/delete-account` - Delete user account

## Security Features
- Password hashing with bcrypt
- JWT authentication
- Two-factor authentication with OTP
- Input validation on both client and server
- Secure file uploads

## Troubleshooting
- Check the `combined.log` and `error.log` files for detailed logs
- Ensure MongoDB is running and accessible
- Verify that all environment variables are correctly set 