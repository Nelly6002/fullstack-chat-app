import test from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import { protectRoute } from "../src/middleware/auth.middleware.js";
import User from "../src/models/user.model.js";

process.env.JWT_SECRET = "test-secret";

test("protectRoute accepts a Bearer token from the authorization header", async () => {
  const userId = "507f1f77bcf86cd799439011";
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" });

  const originalFindById = User.findById;
  User.findById = () => ({
    select: async () => ({ _id: userId, fullName: "Test User", email: "test@example.com" }),
  });

  const req = {
    cookies: {},
    headers: { authorization: `Bearer ${token}` },
  };
  const res = {
    statusCode: 200,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };
  let nextCalled = false;
  const next = () => {
    nextCalled = true;
  };

  await protectRoute(req, res, next);

  assert.equal(res.statusCode, 200);
  assert.equal(nextCalled, true);
  assert.equal(req.user._id, userId);

  User.findById = originalFindById;
});
