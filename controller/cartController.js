const Cart = require('../models/CartModel');
const Course = require('../models/CourseModel');
const CustomErr = require('../utils/CustomErr');
const asyncErrorHandler = require('../utils/ErrorHandler');

// Add course to cart
exports.addToCart = asyncErrorHandler(async (req, res, next) => {
    const { courseId } = req.body; // Get courseId from the request body

    // Validate courseId
    if (!courseId) {
        return next(new CustomErr('Course ID is required', 400));
    }

    // Find the course
    const course = await Course.findById(courseId);
    if (!course) {
        return next(new CustomErr('Course not found', 404));
    }

    // Find or create the user's cart
    let cart = await Cart.findOne({ userId: req.user._id });

    if (!cart) {
        // Create a new cart if it doesn't exist
        cart = await Cart.create({
            userId: req.user._id,
            items: [{ courseId: course._id, name: course.title, price: course.price }] // Ensure all required fields are filled
        });
        return res.status(201).json({
            status: 'success',
            message: 'Course added to cart successfully',
            data: { cart }
        });
    } else {
        // Check if the item already exists in the cart
        const courseExists = cart.items.some(item => item.courseId.equals(courseId));
        if (!courseExists) {
            cart.items.push({ courseId: course._id, name: course.title, price: course.price });
            await cart.save(); // Save the updated cart
            return res.status(200).json({
                status: 'success',
                message: 'Course added to cart successfully',
                data: { cart }
            });
        } else {
            return res.status(200).json({
                status: 'info',
                message: 'Course already exists in cart',
                data: { cart }
            });
        }
    }
});

// Get user's cart
exports.getCart = asyncErrorHandler(async (req, res, next) => {
    let cart;

    try {
        // Attempt to fetch the user's cart
        cart = await Cart.findOne({ userId: req.user._id }).populate({
            path: 'items.courseId',
            select: 'title pic instructor hours level price',
        });
    } catch (err) {
        // If any DB error occurs, forward it
        console.error("Database error fetching cart:", err);
        return next(new CustomErr('Database error while fetching cart', 500));
    }

    // If no cart exists, return an empty cart object (not an error)
    if (!cart) {
        cart = { userId: req.user._id, items: [] };
    }

    res.status(200).json({
        status: 'success',
        data: { cart },
    });
});

// Remove course from cart
exports.removeFromCart = asyncErrorHandler(async (req, res, next) => {
    const { courseId } = req.params; // courseId should be in the request parameters

    // Validate courseId
    if (!courseId) {
        return next(new CustomErr('Course ID is required', 400));
    }

    // Find the user's cart
    let cart = await Cart.findOne({ userId: req.user._id });

    if (!cart) {
        return next(new CustomErr('No cart found for this user', 404));
    }

    // Remove the course from the cart
    cart.items = cart.items.filter(item => !item.courseId.equals(courseId));
    await cart.save();

    // Send back the updated cart
    res.status(200).json({
        status: 'success',
        message: 'Course removed from cart successfully',
        data: { cart }
    });
});
