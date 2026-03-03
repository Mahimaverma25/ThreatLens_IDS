const jwt = require("jsonwebtoken");
const config = require("../config/env");

const authenticate = (req, res, next) => {
	const header = req.headers.authorization;

	if (!header || !header.startsWith("Bearer ")) {
		return res.status(401).json({ message: "Missing or invalid token" });
	}

	const token = header.slice("Bearer ".length).trim();

	try {
		const payload = jwt.verify(token, config.jwtSecret);
		req.user = payload;
		return next();
	} catch (error) {
		return res.status(401).json({ message: "Invalid or expired token" });
	}
};

module.exports = authenticate;
