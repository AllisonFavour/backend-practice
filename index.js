// load environment variables from .env
require("dotenv").config();

// bring jsonwebtoken
const jwt = require("jsonwebtoken");

// bring in mongoose
const mongoose = require("mongoose");

console.log("> connecting to", process.env.MONGODB_URI);

// connect to mongoose
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

const User = require("./models/User");

const express = require("express");
const catchAsync = require("./utils/catchAsync");
const ApiError = require("./utils/ApiError");
// restrictTo
const {restrictTo} = require('./utils/authorize');

const app = express();
const PORT = 3000;

app.use(express.json());

// route protecction with auth middleware
const protect = catchAsync(async (req, res, next) => {
  let token;

  // get token from header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) throw new ApiError(401, "You are not logged in");

  // verify token
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  // check user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) throw new ApiError(401, "User no longer exist");

  req.user = currentUser;
  next();

  // apply protect to routes you want to secure like patch, delete
});

// helper to sign token
const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1h" });

// signup route
app.post(
  "/signup",
  catchAsync(async (req, res) => {
    const { name, email, password, age } = req.body;
    const newUser = await User.create({ name, email, password, age });
    const token = signToken(newUser._id);
    res.status(201).json({ status: "success", token, data: { user: newUser } });
  })
);

// login route
app.post(
  "/login",
  catchAsync(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
      throw new ApiError(400, "Provide Email and Password");

    const user = await User.findOne({ email }).select("+password");
    if (!user || !(await user.correctPassword(password)))
      throw new ApiError(401, "incorrect Email or Password");

    const token = signToken(user._id);
    res.json({ status: "success", token });
  })
);

// create a user
app.post(
  "/users",
  catchAsync(async (req, res) => {
    const user = await User.create(req.body);
    res.status(201).json(user);
  })
);

// only admins can list all users
app.get(
  "/users",
  protect,
  restrictTo('admin'),
  catchAsync(async (req, res) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const skip = (page - 1) * limit;

    const totalDocs = await User.countDocuments();
    const users = await User.find().skip(skip).limit(limit);
    const totalPages = Math.ceil(totalDocs / limit);

    res.json({
      status: 'success',
      data: {
        users,
        meta: {totalDocs, totalPages, page, limit},
      }
    });
  })
);

// get one user
app.get(
  "/users/:id",
  catchAsync(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) throw new ApiError(404, "User not found");
    res.json(user);
  })
);

// update a user
app.patch(
  "/users/:id",
  protect,
  catchAsync(async (req, res) => {
    // only allow admin or the owner
    if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
      return next(new ApiError(403, 'Not your account'));
    }


    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!user) throw new ApiError(404, "User not found");
    res.json(user);
  })
);

// only admins can delete a user
app.delete(
  "/users/:id",
  protect,
  restrictTo('admin'),
  catchAsync(async (req, res) => {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) throw new ApiError(404, "User not found");
    res.status(204).end();
  })
);

// //example sync route, no wrapper needed
// app.get('/', (req, res) => {
//     res.send('Welcome to my Express backend!');
// });

// // async route wrapped by catchAsync
// app.get('/users/:id', catchAsync(async (req, res) => {
//     const {id} = req.params;
//     if (!/^\d+$/.test(id)) {
//         // throw ApiError caught by catchAsync -> global handler
//         throw new ApiError(400, 'User ID must be a number');
//     }

//     // simulate async operation (e.g DataBase fetch)
//     await new Promise(r => setTimeout(r, 500));
//     res.json({id, name: 'User' + id});
// }));

// app.post('/posts', catchAsync(async (req, res) => {
//     const {title, content} = req.body;
//     if (!title || !content) {
//         throw new ApiError(400, 'Title and Content are required');
//     }
//     // simulate saving
//     await new Promise(r => {
//         setTimeout(r, 500);
//         res.status(201).json({title, content})
//     });
// }));

// 404 handler for undefined route
app.use((req, res, next) => {
  next(new ApiError(404, `Route ${req.originalUrl} not found`));
});

// global error handling middleware
app.use((err, req, res, next) => {
  let { statusCode, message } = err;

  // handle mongoose validation error
  if (err.name == "ValidationError") {
    statusCode = 400;
    message = Object.values(err.errors)
      .map((e) => e.message)
      .join(". ");
  }

  // handle duplicate key error (code 11000)
  if (err.code === 11000) {
    statusCode = 400;
    const field = Object.keys(err.keyValue)[0];
    message = `Duplicate field: ${field}. Please use another value!`;
  }

  res.status(statusCode || 500).json({
    status: "error",
    message: message || "Internal Server Error",
  });
});

app.listen(PORT, () => {
  console.log(`Server deh run for http://localhost:${PORT}`);
});
