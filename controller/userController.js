const User = require('../models/UserModel');
const jwt = require('jsonwebtoken');
const CustomErr = require('../utils/CustomErr');
const asyncErrorHandler = require('../utils/ErrorHandler');
const sendEmail = require('../utils/Email');
const crypto = require('crypto');
const mongoose = require("mongoose");


const signToken = id => {
  return  jwt.sign({ id }, process.env.SECRET_STR, {
        expiresIn: process.env.LOGIN_EXPIRES

    });
}
const createSendResponse = (user, statusCode, res) => {
    const token=signToken(user._id);

    res.status(statusCode).json({
        status: 'success',
        token:token,
        data: {
            user
        }
    });
}
const filterReqObj = (obj, ...allowedFields) => {
    const newObj = {};
    Object.keys(obj).forEach(prop => {
        if (allowedFields.includes(prop))
        newObj[prop] = obj[prop];
    })
    return newObj;
}
exports.getUsers = async (req, res) => {
    try {
        const users = await User.find(); // Adjust query based on requirements
        res.status(200).json({
            status: 'success',
            results: users.length,
            data: {
                users
            }
        });
    } catch (err) {
        res.status(400).json({
            status: 'fail',
            message: err.message
        });
    }
};
// src/controller/userController.js



// Get users based on role (students or instructors)
exports.getUsersByRole = async (req, res) => {
    try {
        const { role } = req.params;
        const validRoles = ['student', 'instructor'];

        if (!validRoles.includes(role)) {
            return res.status(400).json({
                status: 'fail',
                message: 'Invalid user role'
            });
        }

        const users = await User.find({ role }); // Fetch users by role
        res.status(200).json({
            status: 'success',
            results: users.length,
            data: {
                users
            }
        });
    } catch (err) {
        res.status(400).json({
            status: 'fail',
            message: err.message
        });
    }
};


exports.updatePassword = asyncErrorHandler(async (req, res, next) => {
    //get the current user data from database
    //because it is called after protect we can find the id
   const user= await User.findById(req.user._id).select('+password');
      //2,check the password
    if (!(await user.comparePasswordInDb(req.body.currentPassword, user.password))) {
        
        return next(new CustomErr("current password you provided is wrong", 401));
    }
user.password = req.body.password;
user.confirmPassword = req.body.confirmPassword;
await user.save();
    createSendResponse(user, 200, res);
})
exports.updateMe = asyncErrorHandler(async (req, res, next) => {
    if (req.body.password || req.body.confirmPassword) {
        return next(new CustomErr("You can not update your password using this endpoints!!!"), 400);
    }
    const filterObj = filterReqObj(req.body,'name','email');
    const user = await User.findByIdAndUpdate(req.user._id, req.body, { runValidators: true, new: true });


     createSendResponse(user, 200, res);
});

exports.deleteMe = asyncErrorHandler(async (req, res, next) => {

    const user= await User.findByIdAndUpdate(req.user._id, { active: false });
    res.status(204).json({
        status: "success",
        message: "successfully deleted",
        data:null
})

})
exports.deleteUser = asyncErrorHandler(async (req, res, next) => {
    console.log("ID received: ", req.params.id);  // Debugging line

    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
        return next(new CustomErr("No user found to delete", 400));
    }

    res.status(204).json({
        status: "success",
        message: "Successfully deleted from database",
        data: null
    });
});
// Get user by ID handler
exports.getUserById = asyncErrorHandler(async (req, res, next) => {
    const userId = req.params.id;

    // Check if ID is a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return next(new CustomErr('Invalid user ID format', 400));
    }

    const user = await User.findById(userId).select('-password');

    if (!user) {
        return next(new CustomErr('User not found', 404));
    }

    res.status(200).json({
        status: 'success',
        data: { user },
    });
});
exports.getMe = asyncErrorHandler(async (req, res, next) => {
  try {
    console.log("📌 Incoming request to /auth/me");
    console.log("Headers:", req.headers);              // Log all headers
    console.log("Authorization header:", req.headers.authorization); 
    console.log("Cookies:", req.cookies);             // Log cookies if any
    console.log("Method:", req.method);               // GET / POST
    console.log("Original URL:", req.originalUrl);    // Path
    console.log("IP:", req.ip);                       // Client IP

    if (!req.user) {
      console.warn("⚠️ No user found in req.user. Token missing or invalid.");
      return res.status(401).json({ message: "Unauthorized: No user info" });
    }

    const user = await User.findById(req.user._id).select('-password'); // Exclude password

    if (!user) {
      console.warn(`⚠️ User not found in DB with id ${req.user._id}`);
      return next(new CustomErr('User not found', 404));
    }

    console.log("✅ User fetched successfully:", user);

    res.status(200).json({
      status: 'success',
      data: { user },
    });

  } catch (err) {
    console.error("❌ Error in getMe:", err);
    next(err);
  }
});



