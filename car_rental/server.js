const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static files from frontend directory
app.use(express.static('../frontend'));

// Serve reset password page
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/reset-password.html'));
});

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/car_rental', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// ====== User Schema ======
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    phone: String,
    password: String,
    role: String, // 'customer', 'vendor', 'rider', 'admin'
    terms_accepted: { type: Boolean, default: false },
    terms_accepted_at: { type: Date, default: null },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});
const User = mongoose.model('User', userSchema);

// ====== Booking Schema ======
const bookingSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    car: String,
    bookingDate: { type: Date, default: Date.now },
    otp: String,
    otpExpiresAt: Date,
    terms_accepted: { type: Boolean, default: false },
    terms_accepted_at: { type: Date, default: null }
});
const Booking = mongoose.model('Booking', bookingSchema);

// ====== Email Transporter (Gmail SMTP) ======
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "gdheepisha@gmail.com", // your email
        pass: "hfqpqxofhngzesdm"   // app password from Gmail
    }
});

// ====== Helper to Generate OTP ======
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// ====== Signup Route ======
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, phone, password, role, terms_accepted } = req.body;
        if (!name || !email || !phone || !password || !role) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        
        // Validate T&C acceptance for customers and riders
        if ((role === 'customer' || role === 'rider' || role === 'vendor') && !terms_accepted) {
            return res.status(400).json({ 
                message: 'Terms & Conditions acceptance is required for customers, riders, and vendors' 
            });
        }
        
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ message: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Prepare user data with T&C acceptance
        const userData = { 
            name, 
            email, 
            phone, 
            password: hashedPassword, 
            role 
        };
        
        // Add T&C data for customers, riders, and vendors
        if (role === 'customer' || role === 'rider' || role === 'vendor') {
            userData.terms_accepted = terms_accepted;
            userData.terms_accepted_at = terms_accepted ? new Date() : null;
        }
        
        const user = new User(userData);
        await user.save();
        
        console.log(`User registered: ${email}, Role: ${role}, T&C Accepted: ${terms_accepted || 'N/A'}`);
        res.status(201).json({ message: 'Signup successful' });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ====== Login Route ======
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        const user = await User.findOne({ email, role });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign(
            { userId: user._id, role: user.role, name: user.name, email: user.email },
            'your_jwt_secret',
            { expiresIn: '2h' }
        );
        res.json({ message: 'Login successful', token, user: { name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ====== Booking Route (Sends OTP) ======
app.post('/api/book', async (req, res) => {
    try {
        const { email, car, terms_accepted } = req.body;
        if (!email || !car) {
            return res.status(400).json({ message: "Email and car are required" });
        }
        
        // Validate T&C acceptance for booking
        if (!terms_accepted) {
            return res.status(400).json({ 
                message: "Terms & Conditions acceptance is required for booking" 
            });
        }
        
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

        // Create booking with T&C acceptance data
        const booking = new Booking({ 
            userId: user._id, 
            car, 
            otp, 
            otpExpiresAt,
            terms_accepted: terms_accepted,
            terms_accepted_at: new Date()
        });
        await booking.save();

        // Send OTP Email
        await transporter.sendMail({
            from: '"Car Rental" <gdheepisha@gmail.com>',
            to: user.email,
            subject: "Your Booking OTP",
            text: `Hello ${user.name},\n\nYour OTP for booking ${car} is ${otp}.\nIt will expire in 5 minutes.`
        });

        console.log(`Booking created: ${car} for ${email}, T&C Accepted: ${terms_accepted}, Time: ${new Date()}`);
        res.json({ message: "Booking created & OTP sent to your email", bookingId: booking._id });
    } catch (err) {
        console.error("Booking error:", err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ====== Verify OTP Route ======
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { bookingId, otp } = req.body;
        const booking = await Booking.findById(bookingId);
        if (!booking) return res.status(404).json({ message: "Booking not found" });

        if (new Date() > booking.otpExpiresAt) {
            return res.status(400).json({ message: "OTP expired" });
        }

        if (booking.otp !== otp) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        res.json({ message: "OTP verified successfully" });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ====== Resend OTP Route ======
app.post('/api/resend-otp', async (req, res) => {
    try {
        const { bookingId } = req.body;
        const booking = await Booking.findById(bookingId);
        if (!booking) return res.status(404).json({ message: "Booking not found" });

        // Generate new OTP
        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

        // Update booking with new OTP
        booking.otp = otp;
        booking.otpExpiresAt = otpExpiresAt;
        await booking.save();

        // Get user details for email
        const user = await User.findById(booking.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        // Send new OTP email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Your New Booking OTP",
            text: `Hello ${user.name},\n\nYour new OTP for booking ${booking.car} is ${otp}.\nIt will expire in 5 minutes.\n\nThank you for choosing Elite Rentals!`
        });

        res.json({ message: "New OTP sent to your email" });
    } catch (err) {
        console.error('Resend OTP error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ====== Forgot Password Route ======
app.post('/auth/forgot-password', async (req, res) => {
    try {
        const { email, role } = req.body;
        
        if (!email || !role) {
            return res.status(400).json({ message: 'Email and role are required' });
        }

        // Find user by email and role
        const user = await User.findOne({ email, role });
        if (!user) {
            return res.status(404).json({ message: 'No account found with this email and role' });
        }

        // Generate reset token (6 digits)
        const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
        const resetExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

        // Save reset token to user
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetExpires;
        await user.save();

        // Create reset URL pointing to our reset password page
        const resetUrl = `http://localhost:5000/reset-password?token=${resetToken}&email=${email}`;

        // Send reset email
        const mailOptions = {
            from: '"Elite Rentals" <gdheepisha@gmail.com>',
            to: email,
            subject: 'Password Reset Request - Elite Rentals',
            html: `
                <div style="font-family: 'Inter', Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #000; color: #fff;">
                    <div style="background: linear-gradient(135deg, #000 0%, #1a1a1a 100%); padding: 2rem; text-align: center; border-bottom: 3px solid #FFD700;">
                        <h1 style="color: #FFD700; font-size: 2rem; margin: 0; text-shadow: 0 0 20px rgba(255, 215, 0, 0.3);">
                            ELITE RENTALS
                        </h1>
                        <p style="color: #ccc; margin: 0.5rem 0 0 0; font-size: 0.9rem;">Premium Car Rental Experience</p>
                    </div>
                    
                    <div style="padding: 2rem; background: #1a1a1a;">
                        <h2 style="color: #FFD700; margin-bottom: 1rem;">Password Reset Request</h2>
                        <p style="color: #ccc; line-height: 1.6; margin-bottom: 1.5rem;">
                            Hello <strong style="color: #FFD700;">${user.name}</strong>,
                        </p>
                        <p style="color: #ccc; line-height: 1.6; margin-bottom: 1.5rem;">
                            We received a request to reset your password for your <strong style="color: #FFD700;">${role}</strong> account. 
                            Use the verification code below to reset your password:
                        </p>
                        
                        <div style="background: #2a2a2a; border: 2px solid #FFD700; border-radius: 8px; padding: 1.5rem; text-align: center; margin: 2rem 0;">
                            <p style="color: #ccc; margin: 0 0 0.5rem 0; font-size: 0.9rem;">Your Reset Code:</p>
                            <h3 style="color: #FFD700; font-size: 2rem; margin: 0; letter-spacing: 0.2em; font-weight: bold;">
                                ${resetToken}
                            </h3>
                        </div>

                        <p style="color: #ccc; line-height: 1.6; margin-bottom: 1.5rem;">
                            Alternatively, you can click the button below to reset your password directly:
                        </p>
                        
                        <div style="text-align: center; margin: 2rem 0;">
                            <a href="${resetUrl}" style="
                                display: inline-block;
                                background: linear-gradient(135deg, #FFD700 0%, #FFA000 100%);
                                color: #000;
                                padding: 1rem 2rem;
                                text-decoration: none;
                                border-radius: 8px;
                                font-weight: bold;
                                font-size: 1rem;
                                box-shadow: 0 4px 15px rgba(255, 215, 0, 0.3);
                                transition: all 0.3s ease;
                            ">Reset Password</a>
                        </div>
                        
                        <div style="background: rgba(255, 68, 68, 0.1); border-left: 4px solid #f44336; padding: 1rem; margin: 2rem 0; border-radius: 4px;">
                            <p style="color: #f44336; margin: 0; font-weight: bold; font-size: 0.9rem;">⚠️ Security Notice:</p>
                            <p style="color: #ccc; margin: 0.5rem 0 0 0; font-size: 0.85rem; line-height: 1.4;">
                                This code will expire in <strong>10 minutes</strong>. If you didn't request this reset, please ignore this email or contact support.
                            </p>
                        </div>
                        
                        <div style="border-top: 1px solid #333; padding-top: 1.5rem; margin-top: 2rem; text-align: center;">
                            <p style="color: #999; font-size: 0.8rem; margin: 0;">
                                Elite Rentals - Premium Car Rental Experience<br>
                                📧 support@eliterentals.com | 📞 +1 (800) ELITE-01
                            </p>
                        </div>
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        
        console.log(`Password reset email sent to: ${email} (${role})`);
        res.json({ 
            message: 'Password reset link has been sent to your email address',
            success: true 
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ 
            message: 'Failed to send reset email. Please try again later.',
            error: error.message 
        });
    }
});

// ====== Reset Password Route ======
app.post('/auth/reset-password', async (req, res) => {
    try {
        const { token, email, newPassword } = req.body;
        
        if (!token || !email || !newPassword) {
            return res.status(400).json({ message: 'Token, email, and new password are required' });
        }

        // Find user with valid reset token
        const user = await User.findOne({
            email: email,
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        // Validate password strength
        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Hash new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update user password and clear reset token
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        // Send confirmation email
        const confirmationMailOptions = {
            from: '"Elite Rentals" <gdheepisha@gmail.com>',
            to: email,
            subject: 'Password Successfully Reset - Elite Rentals',
            html: `
                <div style="font-family: 'Inter', Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #000; color: #fff;">
                    <div style="background: linear-gradient(135deg, #000 0%, #1a1a1a 100%); padding: 2rem; text-align: center; border-bottom: 3px solid #4CAF50;">
                        <h1 style="color: #FFD700; font-size: 2rem; margin: 0;">ELITE RENTALS</h1>
                        <p style="color: #ccc; margin: 0.5rem 0 0 0;">Premium Car Rental Experience</p>
                    </div>
                    
                    <div style="padding: 2rem; background: #1a1a1a;">
                        <div style="text-align: center; margin-bottom: 2rem;">
                            <div style="background: #4CAF50; border-radius: 50%; width: 60px; height: 60px; margin: 0 auto 1rem; display: flex; align-items: center; justify-content: center;">
                                <span style="color: #fff; font-size: 1.5rem;">✓</span>
                            </div>
                            <h2 style="color: #4CAF50; margin: 0;">Password Reset Successful!</h2>
                        </div>
                        
                        <p style="color: #ccc; line-height: 1.6; text-align: center;">
                            Hello <strong style="color: #FFD700;">${user.name}</strong>,<br>
                            Your password has been successfully updated. You can now login with your new password.
                        </p>
                        
                        <div style="text-align: center; margin: 2rem 0;">
                            <p style="color: #999; font-size: 0.9rem;">
                                If you didn't make this change, please contact our support team immediately.
                            </p>
                        </div>
                        
                        <div style="border-top: 1px solid #333; padding-top: 1.5rem; text-align: center;">
                            <p style="color: #999; font-size: 0.8rem; margin: 0;">
                                Elite Rentals Security Team<br>
                                📧 support@eliterentals.com | 📞 +1 (800) ELITE-01
                            </p>
                        </div>
                    </div>
                </div>
            `
        };

        await transporter.sendMail(confirmationMailOptions);
        
        console.log(`Password successfully reset for: ${email}`);
        res.json({ 
            message: 'Password has been successfully reset',
            success: true 
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            message: 'Failed to reset password. Please try again.',
            error: error.message 
        });
    }
});

// ====== Start Server ======
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));





// const express = require('express');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const cors = require('cors');

// const app = express();
// app.use(express.json());
// app.use(cors());

// // MongoDB connection
// mongoose.connect('mongodb://localhost:27017/car_rental', {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
// });

// // User Schema
// const userSchema = new mongoose.Schema({
//     name: String,
//     email: { type: String, unique: true },
//     phone: String,
//     password: String,
//     role: String, // 'customer', 'rider', 'admin'
// });

// const User = mongoose.model('User', userSchema);

// // Signup Route
// app.post('/api/signup', async (req, res) => {
//     try {
//         console.log('Signup payload:', req.body);
//         const { name, email, phone, password, role } = req.body;
//         if (!name || !email || !phone || !password || !role) {
//             console.log('Missing field');
//             return res.status(400).json({ message: 'All fields are required' });
//         }
//         const existing = await User.findOne({ email });
//         if (existing) {
//             console.log('Email exists');
//             return res.status(400).json({ message: 'Email already exists' });
//         }
//         const hashedPassword = await bcrypt.hash(password, 10);
//         const user = new User({ name, email, phone, password: hashedPassword, role });
//         await user.save();
//         console.log('User saved:', user);
//         res.status(201).json({ message: 'Signup successful' });
//     } catch (err) {
//         console.error('Signup error:', err);
//         res.status(500).json({ message: 'Server error', error: err.message });
//     }
// });

// // Login Route
// app.post('/api/login', async (req, res) => {
//     try {
//         const { email, password, role } = req.body;
//         const user = await User.findOne({ email, role });
//         if (!user) return res.status(400).json({ message: 'Invalid credentials' });

//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

//         // Generate JWT
//         const token = jwt.sign(
//             { userId: user._id, role: user.role, name: user.name, email: user.email },
//             'your_jwt_secret',
//             { expiresIn: '2h' }
//         );
//         res.json({ message: 'Login successful', token, user: { name: user.name, email: user.email, role: user.role } });
//     } catch (err) {
//         res.status(500).json({ message: 'Server error', error: err.message });
//     }
// });

// // Start server
// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => console.log(Server running on port ${PORT}));