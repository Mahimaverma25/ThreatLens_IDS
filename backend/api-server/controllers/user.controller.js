const User = require("../models/User");
const { normalizeRole } = require("../utils/roles");

const me = async (req, res) => {
	const user = await User.findById(req.user.sub);

	if (!user) {
		return res.status(404).json({ message: "User not found" });
	}

	if (user.role !== normalizeRole(user.role)) {
		user.role = normalizeRole(user.role);
		await user.save();
	}

	return res.json({ data: user });
};

const listUsers = async (req, res) => {
	const users = await User.find({ _org_id: req.orgId }).sort({ createdAt: -1 });
	users.forEach((user) => {
		user.role = normalizeRole(user.role);
	});
	return res.json({ data: users, total: users.length });
};

module.exports = {
	me,
	listUsers
};
