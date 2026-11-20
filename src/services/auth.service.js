// authentication service

const bcrypt = require('bcrypt');
const User = require('../models/User');
const generateToken = require('../utils/generateToken');
const { sendWelcomeEmail } = require('./email.service');

// REGISTER
const register = async ({ name, email, password, role, adminKey }) => {
    const exists = await User.findOne({ email });

    if (exists) {
        throw new Error('Email already registered');
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Prevent users from assigning themselves admin role
    const userRole =
        role === 'admin' && adminKey === process.env.ADMIN_KEY
            ? 'admin'
            : 'student';

    const user = await User.create({
        name,
        email,
        passwordHash,
        role: userRole,
    });

    const token = generateToken({
        id: user._id,
        role: user.role,
    });

    // Send welcome email without blocking registration
    sendWelcomeEmail(user.email, user.name).catch((err) => {
        console.error('Email sending failed:', err.message);
    });

    return {
        token,
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
        },
    };
};

// LOGIN
const login = async ({ email, password }) => {
    const user = await User.findOne({ email });

    if (!user) {
        throw new Error('Invalid email or password');
    }

    // Compare plain password with bcrypt hashed password
    const match = await bcrypt.compare(password, user.passwordHash);

    if (!match) {
        throw new Error('Invalid email or password');
    }

    const token = generateToken({
        id: user._id,
        role: user.role,
    });

    return {
        token,
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
        },
    };
};

// GET CURRENT USER
const getMe = async (userId) => {
    const user = await User.findById(userId).select('-passwordHash');

    if (!user) {
        throw new Error('User not found');
    }

    return user;
};

module.exports = {
    register,
    login,
    getMe,
};
