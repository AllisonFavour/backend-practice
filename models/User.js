const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// validate email
const emailValidator = {
  validator: (val) => /^\S+@\S+\.\S+$/.test(val),
  message: (props) => `${props.value} is not a valid email!`,
};

// ① Define the shape of your user data
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String, // must be a string
      required: [true, "Name is required"], // cannot be empty
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true, // no two users get same email
      lowercase: true,
      validate: emailValidator,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minLength: 8,
      select: false,
    },
    age: {
      type: Number, // optional numeric field
      min: [0, "Age must be positive"],
    },
    // role field, user or admin
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
  },
  {
    timestamps: true, // auto-create createdAt & updatedAt
  }
);

// pre-save hook: hash password if changed
userSchema.pre("save", async function (next) {
  if (!this.isModified) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// instance method: check password on login
userSchema.methods.correctPassword = async function (candidatePw) {
  return await bcrypt.compare(candidatePw, this.password);
};

// ② Compile schema into a Model
const User = mongoose.model("User", userSchema);

// ③ Export the model for use in routes
module.exports = User;
