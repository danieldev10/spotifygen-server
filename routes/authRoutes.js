import express from 'express'
import { connectToDatabase } from '../lib/db.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import crypto from 'crypto'
import passport from '../lib/passport.js';

const router = express.Router()

// Rate limiter: max 5 requests per 15 minutes per IP
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: { message: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

router.post('/register', authLimiter, async (req, res) => {
    const { username, email, password } = req.body;

    // Password policy: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special char
    const passwordPolicy = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
    if (!passwordPolicy.test(password)) {
        return res.status(400).json({
            message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.'
        });
    }

    try {
        const connection = await connectToDatabase();
        const [rows] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length > 0) {
            return res.status(409).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await connection.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

        return res.status(201).json({ message: 'User created successfully' });

    } catch (err) {
        console.error('Registration error:', err); // Log detailed error
        res.status(500).json({ message: 'Internal server error' }); // Generic error message
    }
});

router.post('/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const connection = await connectToDatabase()
        const [rows] = await connection.query('SELECT * FROM users WHERE email = ?', [email])
        if (rows.length === 0) {
            return res.status(401).json({ message: "Email or password is not correct." })
        }
        const isMatch = await bcrypt.compare(password, rows[0].password)
        if (!isMatch) {
            return res.status(401).json({ message: "Email or password is not correct." })
        }
        const token = jwt.sign(
            { id: rows[0].id, passwordChangedAt: rows[0].passwordChangedAt },
            process.env.JWT_KEY,
            { expiresIn: '3h' }
        );

        return res.status(201).json({ token: token })
    } catch (err) {
        console.error('Login error:', err); // Log detailed error
        return res.status(500).json({ message: 'Internal server error' }) // Generic error message
    }
})

const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(403).json({ message: "No or invalid token provided" })
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(403).json({ message: "No token provided" })
        }
        const decoded = jwt.verify(token, process.env.JWT_KEY);
        const connection = await connectToDatabase();
        const [rows] = await connection.query('SELECT * FROM users WHERE id = ?', [decoded.id]);
        if (!rows.length) return res.status(401).json({ message: 'Invalid token' });
        if (
            rows[0].passwordChangedAt &&
            new Date(rows[0].passwordChangedAt).getTime() > decoded.iat * 1000
        ) {
            return res.status(401).json({ message: 'Token is no longer valid.' });
        }
        req.userId = decoded.id;
        next();
    } catch (err) {
        console.error('Token verification error:', err); // Log detailed error
        return res.status(401).json({ message: "Invalid or expired token" }) // Generic error message
    }
}

router.get('/home', verifyToken, async (req, res) => {
    try {
        const connection = await connectToDatabase()
        const [rows] = await connection.query('SELECT * FROM users WHERE id = ?', [req.userId])
        if (rows.length === 0) {
            return res.status(404).json({ message: "user not existed" })
        }

        return res.status(201).json({ user: rows[0] })
    } catch (err) {
        console.error('Home route error:', err); // Log detailed error
        return res.status(500).json({ message: "Internal server error" }) // Generic error message
    }
})

// Forgot Password: Request reset
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const connection = await connectToDatabase();
        const [rows] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            // Always respond with success to prevent user enumeration
            return res.status(200).json({ message: 'If that email is registered, a reset link has been sent.' });
        }
        // Create a reset token (JWT, expires in 15 min)
        const resetToken = jwt.sign({ id: rows[0].id, passwordChangedAt: rows[0].passwordChangedAt }, process.env.JWT_KEY, { expiresIn: '15m' });
        // Simulate sending email (log to console)
        const resetLink = `http://localhost:5173/reset-password?token=${resetToken}`;
        console.log(`Password reset link for ${email}: ${resetLink}`);
        return res.status(200).json({ message: 'If that email is registered, a reset link has been sent.' });
    } catch (err) {
        console.error('Forgot password error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

// Forgot Password: Reset password
router.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    // Password policy: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special char
    const passwordPolicy = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
    if (!passwordPolicy.test(password)) {
        return res.status(400).json({
            message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.'
        });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_KEY);
        const connection = await connectToDatabase();
        // Check if passwordChangedAt matches (token not used after password change)
        const [rows] = await connection.query('SELECT * FROM users WHERE id = ?', [decoded.id]);
        if (rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired token.' });
        }
        if (rows[0].passwordChangedAt && new Date(rows[0].passwordChangedAt).getTime() > decoded.iat * 1000) {
            return res.status(400).json({ message: 'Token is no longer valid.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await connection.query('UPDATE users SET password = ?, passwordChangedAt = NOW() WHERE id = ?', [hashedPassword, decoded.id]);
        return res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (err) {
        console.error('Reset password error:', err);
        return res.status(400).json({ message: 'Invalid or expired token.' });
    }
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    const jwtToken = jwt.sign({ id: req.user.id }, process.env.JWT_KEY, { expiresIn: '3h' });
    res.redirect(`http://localhost:5173/oauth-success?token=${jwtToken}`);
});

router.get('/spotify', passport.authenticate('spotify', {
    scope: [
        'playlist-modify-public',
        'playlist-modify-private',
        'user-read-email',
        'user-read-private'
    ]
}));

router.get('/spotify/callback', passport.authenticate('spotify', { session: false }), (req, res) => {
    const jwtToken = jwt.sign({ id: req.user.id }, process.env.JWT_KEY, { expiresIn: '3h' });
    res.redirect(`http://localhost:5173/oauth-success?token=${jwtToken}`);
});

export default router;