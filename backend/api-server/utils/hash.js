const crypto = require("crypto");

const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");

const hmacSha256 = (secret, payload) =>
	crypto.createHmac("sha256", String(secret)).update(String(payload)).digest("hex");

module.exports = {
	sha256,
	hmacSha256
};
