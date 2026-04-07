/**
 * Async handler wrapper
 * Catches errors from async route handlers and passes to Express error handler
 * Prevents unhandled promise rejections
 */

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = asyncHandler;
