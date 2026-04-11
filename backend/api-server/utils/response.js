const success = (res, data, message = "OK", status = 200, meta = undefined) => {
	const payload = { success: true, message, data };
	if (meta) {
		payload.meta = meta;
	}
	return res.status(status).json(payload);
};

const error = (res, message = "Request failed", status = 400, details = undefined) => {
	const payload = { success: false, message };
	if (details) {
		payload.details = details;
	}
	return res.status(status).json(payload);
};

module.exports = {
	success,
	error
};
