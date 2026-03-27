const jwt = require("jsonwebtoken");
const config = require("../config/env");

const authenticate = (req, res, next) => {
const apiKey = req.headers["x-api-key"];
const authHeader = req.headers.authorization;

```
// ✅ 1. Allow API Key (for agents / logs ingestion)
if (apiKey) {
	if (apiKey === config.apiKey) {
		req.user = { type: "agent" }; // optional
		return next();
	} else {
		return res.status(401).json({ message: "Invalid API key" });
	}
}

// ✅ 2. Allow JWT (for frontend users)
if (authHeader && authHeader.startsWith("Bearer ")) {
	const token = authHeader.slice("Bearer ".length).trim();

	try {
		const payload = jwt.verify(token, config.jwtSecret);
		req.user = payload;
		return next();
	} catch (error) {
		return res.status(401).json({ message: "Invalid or expired token" });
	}
}

// ❌ If neither provided
return res.status(401).json({ message: "Unauthorized access" });
```

};

module.exports = authenticate;
