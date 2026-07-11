import jwt from "jsonwebtoken";

const getJwtSecret = () => process.env.JWT_SECRET || "fallback-secret";

export const generateToken = (userId, res) => {
  const token = jwt.sign({ userId }, getJwtSecret(), {
    expiresIn: "7d",
  });

  res.cookie("jwt", token, {
    maxAge: 7 * 24 * 60 * 60 * 1000, // MS
    httpOnly: true, // prevent XSS attacks cross-site scripting attacks
    sameSite: process.env.NODE_ENV === "development" ? "lax" : "none",
    secure: process.env.NODE_ENV !== "development",
    path: "/",
  });

  return token;
};
