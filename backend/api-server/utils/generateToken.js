const jwt = require("jsonwebtoken");
const config = require("../config/env");

const generateToken = (payload, expiresIn = config.jwtExpiresIn) =>
	jwt.sign(payload, config.jwtSecret, { expiresIn });

module.exports = generateToken;
