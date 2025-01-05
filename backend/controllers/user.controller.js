import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Controller for register
export const register = async (req, res) => {
  try {
    const { fullname, email, phoneNumber, password, role } = req.body;
    // if any filed keeps blank
    if (!fullname || !email || !phoneNumber || password || !role) {
      return res.status(400).json({
        message: "Something is missing",
        success: false,
      });
    }
    // check same user existence
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        message: "User already exists with this email",
        success: false,
      });
    }
    // password hashing
    const hashedPassword = await bcrypt.hash(password, 6);

    await User.create({
      fullname,
      email,
      phoneNumber,
      password: hashedPassword,
      role,
    });

    return res.status(201).json({
      message: "Account created successfully",
      success: true,
    });
  } catch (error) {
    console.error("Error creating account:", error.message);

    return res.status(500).json({
      message: "Internal Server Error. Please try again later.",
      success: false,
    });
  }
};

// Controller for login
export const login = async (req, res) => {
  try {
    const { email, password, role } = req.body;
    // if any filed keeps blank
    if (!email || !phoneNumber || password || !role) {
      return res.status(400).json({
        message: "All fields are required",
        success: false,
      });
    }
    // if user is not exists in the database
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
        success: false,
      });
    }
    // Check password is correct or not
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({
        message: "Invalid credentials",
        success: false,
      });
    }
    // Check role is correct or not
    if (role != user.role) {
      return res.status(400).json({
        message: "You do not have the appropriate role to access this account.",
        success: false,
      });
    }

    // token generation
    const tokenData = {
      userId: user._id,
    };
    const token = await jwt.sign(tokenData, process.env.JWT_SECRET_KEY, {
      expiresIn: "1d",
    });

    user = {
      _id: user._id,
      fullname: user.fullname,
      email: user.email,
      phoneNumber: user.phoneNumber,
      role: user.role,
      profile: user.profile,
    };

    return res
      .status(200)
      .cookie("token", token, {
        maxAge: 1 * 24 * 60 * 60 * 1000,
        httpsOnly: true,
        sameSite: strict,
      })
      .json.message({
        message: `Welcome back ${fullname}`,
        success: false,
      });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      message: "An error occurred while login. Please try again later.",
      success: false,
    });
  }
};

// Controller for logout
export const logout = async (req, res) => {
  try {
    return res.status(200).json({
      message: "Logged out successfully",
      success: true,
    });
  } catch (error) {
    console.error("Logout error: ", error.message);

    return res.status(500).json({
      message: "An error occurred while logout. Please try again later.",
      success: false,
    });
  }
};

// Controller for profile update
export const profileUpdate = async (req, res) => {
  try {
    const { fullname, email, phoneNumber, bio, skills } = req.body;
    const file = req.file;

    // if any filed keeps blank
    if (!fullname || !email || !phoneNumber || bio || !skills) {
      return res.status(400).json({
        message: "Something is missing",
        success: false,
      });
    }

    const skillsArray = skills.split(",");
    const userId = req.id; // middleware authentication
    let user = await User.findById(userId);

    if (!user) {
      return res.status(401).json({
        message: "User not found",
        success: false,
      });
    }

    // Updating data
    (user.fullname = fullname),
      (user.email = email),
      (user.phoneNumber = phoneNumber),
      (user.profile.bio = bio),
      (user.profile.skills = skillsArray);

    await user.save();

    user = {
      _id: user._id,
      fullname: user.fullname,
      email: user.email,
      phoneNumber: user.phoneNumber,
      role: user.role,
      profile: user.profile,
    };

    return res.status(200).message({
      message: "Profile updated successfully",
      user,
      success: true,
    });
  } catch (error) {
    console.error("Profile update error: ", error.message);

    return res.status(500).json({
      message:
        "An error occurred while updating your profile. Please try again later.",
      success: false,
    });
  }
};
