import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

const getJwtSecret = () => process.env.JWT_SECRET || "fallback-secret";

export const protectRoute = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || "";
    const tokenFromCookie = req.cookies?.jwt;
    const token = tokenFromCookie || (authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null);

    if (!token) {
      return res.status(401).json({ message: "Unauthorized - No Token Provided" });
    }

    const decoded = jwt.verify(token, getJwtSecret());

    if (!decoded?.userId) {
      return res.status(401).json({ message: "Unauthorized - Invalid Token" });
    }

    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;

    next();
  } catch (error) {
    console.log("Error in protectRoute middleware: ", error.message);
    return res.status(401).json({ message: "Unauthorized - Invalid Token" });
  }
};
