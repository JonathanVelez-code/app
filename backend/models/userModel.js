const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); //encrypt password deletion necessary for frontend.

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, "please enter a name"]
    },
    email: {
        type: String,
        required: [true, "please enter a email address"],
        unique: true,
        trim: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "please enter a valid email address"
        ]
    },
    password: {
        type: String,
        required: [true, "please add a password"],
        minLength: [6, "password must be at least 6 characters"],
        //maxLength: [22, "password must be at most 22 characters"]
    },
    phoneNumber: {
        type: String,
        unique: true,
    }
}, {
    timestamps: true,
})

//encrypt password can delete later
userSchema.pre("save", async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
});

const User = mongoose.model('User', userSchema);
module.exports = User;