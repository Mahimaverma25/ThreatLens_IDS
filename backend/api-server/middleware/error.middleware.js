const notFound = (req, res) => {
	return res.status(404).json({ message: "Route not found" });
};

const errorHandler = (err, req, res, next) => {
	if (res.headersSent) {
		return next(err);
	}

	const statusCode = err.statusCode || 500;
	return res.status(statusCode).json({
		message:
			process.env.NODE_ENV === "production"
				? "Internal server error"
				: err.message || "Internal server error"
	});
};

module.exports = {
	notFound,
	errorHandler
};
