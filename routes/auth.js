const router = require("express").Router();
const { User } = require("../models/User");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const authenticate = require("../middleware/authenticate");

router.post("/", async (req, res) => {
	try {
		const { error } = validate(req.body);
		if (error)
			return res.status(400).send({ message: error.details[0].message });

		const user = await User.findOne({ email: req.body.email });
		if (!user)
			return res.status(401).send({ message: "Invalid Email or Password" });

		const validPassword = await bcrypt.compare(
			req.body.password,
			user.password
		);
		if (!validPassword)
			return res.status(401).send({ message: "Invalid Email or Password" });

		const token = await user.generateAuthToken();
		res.cookie("jwtoken", token, {
			expires: new Date(Date.now() + 604800000),
			httpOnly: true
		});
		res.status(200).send({ data: token, message: "logged in successfully" });
	} catch (error) {
		res.status(500).send({ message: "Internal Server Error" });
	}
});

router.get('/', authenticate, (req, res) => {
	res.send(req.rootUser);
})

const validate = (data) => {
	const schema = Joi.object({
		email: Joi.string().email().required().label("Email"),
		password: Joi.string().required().label("Password"),
	});
	return schema.validate(data);
};



module.exports = router;