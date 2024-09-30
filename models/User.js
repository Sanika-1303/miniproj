const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const passwordComplexity = require("joi-password-complexity");

const userSchema = new mongoose.Schema({
	firstName: { type: String, required: true },
	lastName: { type: String, required: true },
	email: { type: String, required: true },
	password: { type: String, required: true },
	tokens: [
		{
			token: {
				type: String, 
				required: true
			}
		}
	]
});

userSchema.methods.generateAuthToken = async function () {
	try{
		let token = jwt.sign({ _id: this._id }, process.env.JWTPRIVATEKEY);
		this.tokens = this.tokens.concat({token:token})
		await this.save();
		return token;
	}catch(err){
		console.log(err);
	}
	
};

const User = mongoose.model("user", userSchema);

const validate = (data) => {
	const schema = Joi.object({
		firstName: Joi.string().required().label("First Name"),
		lastName: Joi.string().required().label("Last Name"),
		email: Joi.string().email().required().label("Email"),
		password: passwordComplexity().required().label("Password"),
	});
	return schema.validate(data);
};

module.exports = { User, validate };