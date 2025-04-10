const User = require("../models/User");
const bcrybt = require("bcryptjs");
const { StatusCodes } = require("http-status-codes");
const { UnauthenticatedError } = require("../errors");
const register = async (req, res) => {
  const user = await User.create(req.body);
  const token = user.createJWT();
  res.status(StatusCodes.CREATED).json({ user, token });
};
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new BadRequestError("Please provide email and password");
  }
  const user = await User.findOne({ email });
  if (!user) {
    throw new UnauthenticatedError("Invalid Credentials");
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Invalid Credentials");
  }
  const token = user.createJWT();
  // console.log(token);

  res.status(StatusCodes.OK).json({ user: { name: user.name }, token });
};
module.exports = {
  loginUser,
  register,
};
