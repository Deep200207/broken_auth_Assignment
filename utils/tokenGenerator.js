const jwt = require("jsonwebtoken");

const generateToken = async (payload) => {
  const secret = process.env.JWT_SECRET;

  return jwt.sign(
    payload,   //
    secret,
    { expiresIn: "15m" }
  );
};

module.exports = { generateToken };
