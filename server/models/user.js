import Mongoose, { Schema } from "mongoose";
import mongoosePaginate from "mongoose-paginate";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate";
import userType from "../enums/userType"; 
import status from "../enums/status";
import bcrypt from "bcryptjs"; 
import config from "config";
import { type } from "joi/lib/types/object";
const axios = require('axios'); 

const options = {
  collection: "user",
  timestamps: true,
};

const userSchema = new Schema(
  {
    fullName: { type: String },
    firstName: { type: String },
    lastName: { type: String }, 
    email: { type: String },
    profilePic: { type: String, default: "" }, 
    gender: { type: String }, 
    mobileNumber: { type: String, required: false },
    countryCode:{
      type:String
    },
    psychiatristsId:{
      type:String
    },
    password: { type: String },  
    confirmPassword:{type:String},
    otp: { type: Number },
    otp2: { type: Number },
    otpTime: { type: Number },  
    address: { type: String },  
    zipCode: { type: String },  
    dateOfBirth: { type: String },   
    otpVerification: { type: Boolean, default: false }, 
    userType: {
      type: String,
      enum: [userType.ADMIN, userType.USER, userType.SUB_ADMIN, userType.PSYCHIATRIST],
      default: userType.USER,
    },
    status: {
      type: String,
      enum: [status.ACTIVE, status.BLOCK, status.DELETE],
      default: status.ACTIVE,
    },
    hospital: { type: String, required: false },
    otpEmail: { type: Number },
    otpTimeEmail: { type: Number },
    
    otpMobile: { type: Number },
    otpTimeMobile: { type: Number },
     
  },
  options
);

userSchema.plugin(mongoosePaginate);
userSchema.plugin(mongooseAggregatePaginate);

const userModel = Mongoose.model("user", userSchema);

module.exports = userModel;

(async () => {
  try {
    // Check for default admin
    const adminResult = await userModel.find({
      userType: userType.ADMIN,
    });
    if (adminResult.length !== 0) {
      console.log("Default Admin 😀 .");
    } else {
      const createdAdmin = await userModel.create({
        userType: userType.ADMIN,
        fullName: "Hritik Bhadaura",
        countryCode: "+91",
        mobileNumber: "7388503329",
        email: "choreohritik52@gmail.com",
        dateOfBirth: "20/08/2001",
        gender: "Male",
        password: bcrypt.hashSync("Mobiloitte@1"),
        address: "Okhala, Delhi, India",
      });
      if (createdAdmin) {
        console.log("DEFAULT ADMIN Created 😀 ", createdAdmin);
      }
    }

    // Add static psychiatrists
    const hospitalName = "Apollo Hospital"; // Assuming hospital name is predefined
    const psychiatrists = [
      {
        fullName: "Dr. John Doe",
        email: "johndoe@mailinator.com",
        userType: userType.PSYCHIATRIST,
        hospital: hospitalName,
        password: bcrypt.hashSync("Mobiloitte@1"),
      },
      {
        fullName: "Dr. Jane Smith",
        email: "janesmith@mailinator.com",
        userType: userType.PSYCHIATRIST,
        hospital: hospitalName,
        password: bcrypt.hashSync("Mobiloitte@1"),
      },
      {
        fullName: "Dr. Emily Johnson",
        email: "emilyjohnson@mailinator.com",
        userType: userType.PSYCHIATRIST,
        hospital: hospitalName,
        password: bcrypt.hashSync("Mobiloitte@1"),
      },
      {
        fullName: "Dr. Michael Brown",
        email: "michaelbrown@mailinator.com",
        userType: userType.PSYCHIATRIST,
        hospital: hospitalName,
        password: bcrypt.hashSync("Mobiloitte@1"),
      },
      {
        fullName: "Dr. Sarah Davis",
        email: "sarahdavis@mailinator.com",
        userType: userType.PSYCHIATRIST,
        hospital: hospitalName,
        password: bcrypt.hashSync("Mobiloitte@1"),
      },
    ];

    for (const psychiatrist of psychiatrists) {
      const existingPsychiatrist = await userModel.findOne({
        email: psychiatrist.email,
      });
      if (!existingPsychiatrist) {
        await userModel.create(psychiatrist);
      }
    }

    console.log("Static psychiatrists created successfully.");
  } catch (error) {
    console.log("Error creating admin or psychiatrists:", error);
  }
})();
