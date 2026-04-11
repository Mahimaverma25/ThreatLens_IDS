const bcrypt = require("bcryptjs");
const { generateAccessToken, generateRefreshToken } = require("../utils/tokens");

const hashPassword = (password) => bcrypt.hash(password, 12);
const comparePassword = (password, passwordHash) => bcrypt.compare(password, passwordHash);

const issueAuthTokens = (user) => ({
	accessToken: generateAccessToken(user),
	refreshToken: generateRefreshToken()
});

module.exports = {
	hashPassword,
	comparePassword,
	issueAuthTokens
};
