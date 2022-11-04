const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Token = require('../models/tokenModels');
const crypto = require('crypto');

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIN: '1d' });
};

//register user
const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        res.status(400);
        throw new Error("please fill in all required fields");
    }
    if (password.length < 6) {
        res.status(400);
        throw new Error("password must be at least 6 characters");
    }
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400);
        throw new Error("Email already exists");
    }

    //create new users
    const user = await User.create({
        name,
        email,
        password,
    });

    // generate token
    const token = generateToken(user._id);

    //send cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //1 day expires
        sameSite: "none",
        secure: true
    });

    if (user) {
        const { _id, name, email, password, phoneNumber } = user;
        res.status(201).json({
            _id, name, email, password, phoneNumber, token
        });
    } else {
        res.status(400);
        throw new Error("Invalid user data");
    }

});

//login user
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    //validate request
    if (!email || !password) {
        res.status(400);
        throw new Error("please add email and password");
    }

    const user = await User.findOne({ email });

    //check for user already exists
    if (!user) {
        res.status(400);
        throw new Error("user not found");
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (user && passwordIsCorrect) {
        const { _id, name, email, password, phoneNumber } = user;
        res.status(201).json({
            _id, name, email, password, phoneNumber, token
        });
    }
    else {
        res.status(400);
        throw new Error("Invalid email or password");
    }

});

//logout user
const logout = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0), //the token expires making the user logout.
        sameSite: "none",
        secure: true
    });
    return res.status(200).json({ message: "Success Logged Out." });
});

//get user data
const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, phoneNumber } = user;
        res.status(201).json({
            _id, name, email, phoneNumber
        });
    }
    else {
        res.status(404);
        throw new Error("User not found");
    }
});

//get login status
const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false);
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true);
    }
    return res.json(false);

});

const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, email, phoneNumber } = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phoneNumber = req.body.phoneNumber || phoneNumber;

        const updateUser = await user.save();
        res.status(200).json({
            id: updateUser._id, name: updateUser.name, email: updateUser.email, phoneNumber: updateUser.phoneNumber
        });
    }
    else {
        res.status(404);
        throw new Error('user not found');
    }

});

const changePassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    const { oldPassword, password } = req.body;

    //validate
    if (!user) {
        res.status(400);
        throw new Error("User not found, please signup");
    }

    //validate
    if (!oldPassword || !password) {
        res.status(400);
        throw new Error("Please add old and new password");
    }

    //check if old password matches password in DB
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    //save new password
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save();
        res.status(200).send("Password changed successfully");
    }
    else {
        res.status(400);
        throw new Error("Old password is incorrect");
    }

});

const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    //delete token if it exists in DB
    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    //create reset token for new password
    let resetToken = crypto.randomBytes(32).toString("hex") + user._id;

    //hash token before saving to database
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    //save token to database
    await new Token({
        userId: user._id,
        token: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * (60 * 1000) //30 minutes
    }).save()

    //construct reset url 
    const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;
    const message = `<h2>Hello ${user.name} </h2>
    <p> Please use the url below to reset your password </p>
    <p> This reset link is valid for only 30 minutes. </p> 
    <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
    <p> Regards TeamName </p>`;

    const subject = 'Password reset request';
    const send_to = user.email;
    const sent_from = process.env.EMIAL_USER;

    try {
        await sendEmail(subject, message, send_to, send_from);
        res.status(200).json({ success: true, message: 'Reste Email sent successfully' });
    } catch (error) {
        res.status(500);
        throw new Error('Email not sent, please try again');
    }

});

//Reset password
const resetPassword = asyncHandler(async (req, res) => {

    const { password } = req.body;
    const { resetToken } = req.params;

    //hash token, then compare the token in database
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    const userToken = await Token.findOne({
        token: hashedToken,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired token");
    }

    //find the user
    const user = await User.findOne({ _id: userToken.userId });
    user.password = password;
    await user.save();
    res.status(200).json({
        messages: "Password reset successful, please login."
    });

});


module.exports = {
    registerUser,
    loginUser,
    logout,
    getUser,
    loginStatus,
    updateUser,
    changePassword,
    forgotPassword,
    resetPassword,
};