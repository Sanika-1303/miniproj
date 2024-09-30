const User = require("../models/User");
const jwt = require("jsonwebtoken");

const Authenticate = async (req, res, next) => {
    try {

        const token = req.cookies.jwtoken;
        const verifyToken = jwt.verify(token, process.env.JWTPRIVATEKEY);

        const rootUser = await User.findOne({ id: verifyToken._id, "tokens.token": token });

        if (!rootUser) { throw new Error('User not Found') }

        req.token = token;
        req.rootUser = rootUser;
        req.userID = rootUser._id;

        next();

    } catch (err) {
        res.status(401).send('Unauthorized: No token provided');
        console.log(err);
    }
}

module.exports = Authenticate;