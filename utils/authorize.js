const ApiError = require('./ApiError');

exports.restrictTo = (...allowedRoles) => {
    return (req, res, next) => {
        // req.user must be set by protect() already
        if (!allowedRoles.includes(req.user.role)) {
            return next(new ApiError(403, 'You do not have permission to perform this action.'));
        }
        next();
    }
}