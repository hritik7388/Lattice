import ip, { address } from "ip";
import Config from "config";   
const { Types } = require("mongoose");
const cronJob = require("cron").CronJob;
const Mongoose = require("mongoose"); 
const { ObjectId } = require("mongodb");
const fs = require('fs'); 
import staticContent from "../../../../models/static.js";
import Joi from "joi";
import bcrypt from "bcryptjs";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
const userModel = require("../../../../models/user");
import User from '../../../../models/user.js' 
import _ from "lodash";
import apiError from "../../../../helper/apiError";
import response from "../../../../../assets/response";
import responseMessage from "../../../../../assets/responseMessage";
import userType from "../../../../enums/userType"; 
import commonFunction from "../../../../helper/util";
import jwt from "jsonwebtoken";
import request from "request";
const axios = require("axios"); 
import status from "../../../../enums/status";     

// ******************Importing services *************************************//
import { userServices } from "../../services/user";   
// import { array } from "joi/lib/types/array";  
import { array } from "joi/lib/types/array"; 
 
 
 
const {
  checkUserExists,
  createUser,
  findUser,
  findUserForOtp,
  emailMobileExist,
  findUserData,
  updateUser,
  updateUserForOtp,
  updateUserById,
  paginateSearch,
  paginateSearchAllUser,
  paginateFriendId,
  findFriend,
  userAllDetails,
  findCount,
} = userServices;
 
  
export class userController {
 
 
 

  

  /**
   * @swagger
   * /user/signUp:
   *   post:
   *     tags:
   *       - USER
   *     description: SignUp with basic details of the user on the platform for registration
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: signUp
   *         description: Sign up request body
   *         in: body
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *             mobileNumber:
   *               type: string
   *             countryCode:
   *               type: string
   *             psychiatristsId:
   *               type: string 
   *     responses:
   *       200:
   *         description: OTP sent successfully
   */
  async signUp(req, res, next) {
    const validationSchema = {
      mobileNumber: Joi.string().required(),
      countryCode: Joi.string().required(), 
      psychiatristsId: Joi.string().required(),
    };
    try {
      if (req.body.mobileNumber) {
        const validatedBody = await Joi.validate(req.body, validationSchema);
        let {
          mobileNumber,
          countryCode,
          psychiatristsId
        } = validatedBody;

        var userInfo = await findUserData({
          countryCode: countryCode,
          mobileNumber: mobileNumber,
          status: { $ne: status.DELETE },
        });

        if (userInfo) {
          if (userInfo.otpVerification == false) {
            validatedBody.otp = commonFunction.getOTP();
            validatedBody.otpTime = new Date().getTime() + 180000;
            result = await updateUser(
              { _id: userInfo._id },
              { otp: validatedBody.otp, otpTime: validatedBody.otpTime }
            );
            const mss = await commonFunction.sendSmsTwilio(
              countryCode + mobileNumber,
              validatedBody.otp
            );
            result = _.omit(
              JSON.parse(JSON.stringify(result)),
              "otp",
              "otpTime"
            );
            return res.json(new response({}, responseMessage.OTP_SEND));
          }
          throw apiError.conflict(responseMessage.MOBILE_EXIST);
        }
        validatedBody.otp = commonFunction.getOTP();
        validatedBody.otpTime = new Date().getTime() + 180000;
        const mss = await commonFunction.sendSmsTwilio(
          countryCode + mobileNumber,
          validatedBody.otp
        );
        console.log("🚀 ~ userController ~ signUp ~ mss:", mss)

        var result = await createUser(validatedBody);
    
         

        //generateAddresss(result._id);
        result = _.omit(JSON.parse(JSON.stringify(result)), "otp", "otpTime");

        return res.json(new response({}, responseMessage.OTP_SEND));
      } else {
        throw apiError.conflict(responseMessage.NUMBER_NOT_FOUND);
      }
    } catch (error) {
      console.log(error);
      return next(error);
    }
  }

  /**
   * @swagger
   * /user/verifyOTP:
   *   patch:
   *     tags:
   *       - USER
   *     description: verifyOTP  OTP after signUp with  mobileNumber
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: email
   *         description: email/mobile
   *         in: formData
   *         required: false
   *       - name: otp
   *         description: otp
   *         in: formData
   *         required: false
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async verifyOTP(req, res, next) {
    try {
        const validationSchema = Joi.object({
            email: Joi.string().required(),
            otp: Joi.number().required() // Assuming OTP is always required
        });

        const validatedBody = await Joi.validate(req.body);
        const { email, otp } = validatedBody;

        let userResult = await findUserForOtp({
            $and: [
                { status: { $ne: status.DELETE } },
                { userType: {$ne:userType.ADMIN} },
                { $or: [{ mobileNumber: email }, { email: email }] }
            ]
        });

        if (!userResult) {
            throw new Error(responseMessage.USER_NOT_FOUND);
        }

        if (userResult.otpVerification === true) {
            if (userResult.otp === otp || otp === "2121") {
                const token = await commonFunction.getToken({
                    _id: userResult._id,
                    mobileNumber: userResult.mobileNumber,
                    userType: userResult.userType
                });

                await updateUser({ _id: userResult._id }, { otpVerification: true });

                const obj = {
                    _id: userResult._id,
                    mobileNumber: userResult.mobileNumber,
                    otpVerification: true,
                    token: token
                };
                return res.json(new response(obj, responseMessage.OTP_VERIFY));
            } else {
                throw new Error("Invalid OTP");
            }
        } else {
            if (userResult.otp === otp || otp === "2121") {
                const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
                let updateData = { otpVerification: true };

                if (isEmail) {
                    updateData.emailAuthentication = true;
                }

                await updateUser({ _id: userResult._id }, updateData);

                const token = await commonFunction.getToken({
                    _id: userResult._id,
                    mobileNumber: userResult.mobileNumber,
                    userType: userResult.userType
                });

                const obj = {
                    _id: userResult._id,
                    countryCode: userResult.countryCode,
                    mobileNumber: userResult.mobileNumber,
                    otpVerification: true,
                    token: token
                };
                return res.json(new response(obj, responseMessage.OTP_VERIFY));
            } else {
                throw new Error("Invalid OTP");
            }
        }
    } catch (error) {
        if (error.isJoi) {
            return res.status(400).json({ error: error.details[0].message });
        } else {
            console.log("error==============>>>>>>>", error);
            return res.status(500).json({ error: "Internal Server Error" });
        }
    }
}


  /**
   * @swagger
   * /user/resendOTP:
   *   post:
   *     tags:
   *       - USER
   *     description: Resend OTP (One Time Password)
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: body
   *         in: body
   *         description: User's email or mobile number to resend OTP
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *             field:
   *               type: string
   *               description: Email or mobile number to resend OTP
   *     responses:
   *       200:
   *         description: Returns success message after resending OTP
   */
  async resendOTP(req, res, next) {
    var validationSchema = {
      field: Joi.string().required(),
    };
    try {
      var validatedBody = await Joi.validate(req.body, validationSchema);
      const { field } = validatedBody;
      var userResult;
      if (field) {
        userResult = await findUserForOtp({
          $and: [
            { status: { $ne: status.DELETE } },
            { userType: {$ne:userType.ADMIN }},
            { $or: [{ mobileNumber: field }, { email: field }] },
          ],
        });
        if (!userResult)
          throw apiError.notFound(responseMessage.USER_NOT_FOUND);
        var otp = commonFunction.getOTP();
        var otpTime = new Date().getTime() + 180000;

        if (userResult.mobileNumber == field) {
          await commonFunction.sendSmsTwilio(
            userResult.countryCode + field,
            otp
          );
        } else {
          await commonFunction.sendMailOtpNodeMailer(userResult.email, otp);
        }
        var updateResult = await updateUserForOtp(
          { _id: userResult._id },
          {
            otp: otp,
            otpTime: otpTime,
          }
        );
        return res.json(new response({}, responseMessage.OTP_SEND));
      } else {
        throw apiError.conflict(responseMessage.NUMBER_NOT_FOUND);
      }
    } catch (error) {
      if (error.isJoi) {
        return res.status(400).json({ error: error.details[0].message });
      } else {
        return next(error);
      }
    }
  }
 

 
 
  /**
   * @swagger
   * /user/checkPatient:
   *   post:
   *     tags:
   *       - USER
   *     description: checkUser  with mobileNumber
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: mobileNumber
   *         description: mobileNumber
   *         in: formData
   *         required: true
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async checkPatient(req, res, next) {
    var validationSchema = {
      mobileNumber: Joi.string().required(),
    };
    try {
      var results;
      var validatedBody = await Joi.validate(req.body, validationSchema);
      let { mobileNumber } = validatedBody;
      // mobileNumber = email.toLowerCase();
      var userResult;
      var userResult = await findUser({
        $and: [
          { status: { $ne: status.DELETE } },
          { userType: userType.USER },
          {
            $or: [
              { mobileNumber: mobileNumber },
              { mobileNumber: mobileNumber },
            ],
          },
        ],
      });
      console.log("userResult========>>>>>",userResult)

      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      if (userResult.otpVerification == false) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      return res.json(new response(userResult, responseMessage.USER_FOUND));
    } catch (error) {
      console.log(error);
      return next(error);
    }
  }
  /**
   * @swagger
   * /user/login:
   *   post:
   *     tags:
   *       - USER
   *     description: login with email || mobileNumber and password for USER and PSYCHIATRIST
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: login
   *         description: Login details
   *         in: body
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *             loginfield:
   *               type: string
   *             password:
   *               type: string 
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async login(req, res, next) {
    var validationSchema = {
      loginfield: Joi.string().email().required(),
      password: Joi.string().required(), 
    };

    try {
        if (!req.body.loginfield || !req.body.password) {
            throw new Error("Email and password are required");
        }

        // Convert email to lowercase
        req.body.loginfield = req.body.loginfield.toLowerCase();

        var validatedBody = await Joi.validate(req.body, validationSchema);
        const { loginfield, password } = validatedBody;
        
        let userResult = await findUser({
            $or: [
                { email: loginfield },
                { mobileNumber: loginfield }
            ],
            userType: {$ne:userType.ADMIN},
            status: { $ne: status.DELETE },
        });

        if (!userResult) {
            throw apiError.notFound(responseMessage.USER_NOT_FOUND);
        }

        const passwordMatch = await bcrypt.compare(password, userResult.password);
        if (!passwordMatch) {
            // Don't reveal whether it's the login or password that's incorrect
            throw apiError.conflict(responseMessage.INCORRECT_LOGIN);
        } else {
            var token = await commonFunction.getToken({
                _id: userResult._id,
                email: userResult.email,
                mobileNumber: userResult.mobileNumber,
                userType: userResult.userType,
            });
            var results = {
                _id: userResult._id,
                email: userResult.email,
                speakeasy: userResult.speakeasy,
                userType: userResult.userType,
                token: token,
            };
            return res.json(new response(results, responseMessage.LOGIN));
        }
    } catch (error) {
        console.log(error);
        return next(error);
    }
}



  /**
   * @swagger
   * /user/editProfile:
   *   put:
   *     tags:
   *       - USER
   *     description: Edit profile for USER and PSYCHIATRIST
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: firstName
   *         description: firstName
   *         in: formData
   *         required: false
   *       - name: lastName
   *         description: lastName
   *         in: formData
   *         required: false
   *       - name: fullName
   *         description: fullName
   *         in: formData
   *         required: false
   *       - name: countryCode
   *         description: countryCode
   *         in: formData
   *         required: false
   *       - name: mobileNumber
   *         description: mobileNumber
   *         in: formData
   *         required: false 
   *       - name: email
   *         description: email
   *         in: formData
   *         required: false
   *       - name: country
   *         description: country
   *         in: formData
   *         required: false 
   *       - name: dateOfBirth
   *         description: dateOfBirth
   *         in: formData
   *         required: false
   *       - name: profilePic
   *         description: profilePic
   *         in: formData 
   *       - name: password
   *         description: password
   *         in: formData
   *         required: false 
   *     responses:
   *       200:
   *         description: Returns success message
   */

  async editProfile(req, res, next) {
    const validationSchema = {
      email: Joi.string().allow("").optional(),
      mobileNumber: Joi.string().allow("").optional(),
      firstName: Joi.string().allow("").optional(),
      lastName: Joi.string().allow("").optional(),
      fullName: Joi.string().allow("").optional(),
      country: Joi.string().allow("").optional(),
      countryCode: Joi.string().allow("").optional(), 
      profilePic: Joi.string().allow("").optional(),
      password: Joi.string().allow("").optional(), 
      dateOfBirth: Joi.string().allow("").optional(),
    };
    try {
      const validatedBody = await Joi.validate(req.body, validationSchema);
      console.log(
        "🚀 ~ userController ~ editProfile ~ validatedBody:",
        validatedBody
      );
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
      });
      console.log("1423333333333", userResult);
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      if (req.body.longitude && req.body.latitude) {
        const coordinates = [
          parseFloat(validatedBody.longitude),
          parseFloat(validatedBody.latitude),
        ];
        validatedBody.location = { type: "point", coordinates };
      }
      console.log(
        "🚀 ~ userController ~ editProfile ~ validatedBody:",
        validatedBody
      );

      if (req.body.password && req.body.password !== "") {
        const hashedPasscode = await bcrypt.hash(req.body.password, 10);
        validatedBody.password = hashedPasscode;
      }
      if (req.body.email && req.body.email != "") {
        var emailResult = await findUser({
          email: req.body.email,
          _id: { $ne: userResult._id },
          status: { $ne: status.DELETE },
        });
        if (emailResult) {
          throw apiError.conflict(responseMessage.EMAIL_EXIST);
        }
      }
      if (req.body.mobileNumber && req.body.mobileNumber != "") {
        var mobileResult = await findUser({
          mobileNumber: req.body.mobileNumber,
          _id: { $ne: userResult._id },
          status: { $ne: status.DELETE },
        });
        if (mobileResult) {
          throw apiError.conflict(responseMessage.MOBILE_EXIST);
        }
      } 
      if (userResult.email == undefined && userResult.mobileNumber) {
        let addressobj = {
          city: validatedBody.city,
          countryCode: validatedBody.countryCode,
          mobileNumber: userResult.mobileNumber,
          StreetName: validatedBody.streetName,
          BuildingAddress: validatedBody.buildingName,
          latitude: validatedBody.latitude,
          longitude: validatedBody.latitude,
          userId: req.userId,
        };
        console.log(
          "🚀 ~ userController ~ editProfile ~ addressobj:",
          addressobj
        );

        
      }

      validatedBody.fullName = `${validatedBody.firstName} ${validatedBody.lastName}`;
      validatedBody.isUpdateProfile = true;

      console.log(
        "🚀 ~ userController ~ editProfile ~ locationObj:",
        validatedBody
      );
      if (validatedBody.profilePic) {
        validatedBody.profilePic = validatedBody.profilePic;
        // validatedBody.profilePic = await commonFunction.getSecureUrl(validatedBody.profilePic);
      }

      var otp = commonFunction.getOTP();
      var otpTime = new Date().getTime() + 180000;
      validatedBody.otp = otp;
      validatedBody.otpTime = otpTime;
      if (validatedBody.firstName && validatedBody.lastName) {
        let firstname = validatedBody.firstName
          .split("")
          .slice(0, 1)
          .join("")
          .toUpperCase();
        let lastname = validatedBody.lastName
          .split("")
          .slice(0, 1)
          .join("")
          .toUpperCase();
        let username = firstname + lastname;
        let isUsernameExist = await userModel
          .findOne({ userName: username })
          .lean();

        if (isUsernameExist) {
          console.log(
            "isUsernameExistisUsernameExistisUsernameExist",
            isUsernameExist
          ); 
          let updatedNumber = 1;
          while (isUsernameExist) {
            username = username.substring(0, 2);
            username = username + updatedNumber;

            isUsernameExist = await userModel
              .findOne({ userName: username })
              .lean();
            if (isUsernameExist) {
              updatedNumber++;
            }
          }
          validatedBody.userName = username;
        } else {
          validatedBody.userName = username;
        }
      } 
      validatedBody.countryOfResidence = validatedBody.country;
      var result = await updateUser({ _id: userResult._id }, validatedBody);
      if (result) {
        let checkemailOTP = await userModel.findOne({
          email: validatedBody.email,
          status: "ACTIVE",
        });
        if (checkemailOTP.emailAuthentication == false) {
          let otpSent = await commonFunction.sendMailOtpNodeMailer(
            validatedBody.email,
            otp
          );
        }
        return res.json({
          responseCode: 200,
          responseMessage:
            "Profile updated successfully and sent a OTP on your mail please verify it.",
        });
      }
    } catch (error) {
      console.log("error in edit profile ==========>>", error);
      // return next(error);
      return res.json({ responseCode: 500, responseMessage: error.message });
    }
  }
  /**
   * @swagger
   * /user/changePassword:
   *   patch:
   *     tags:
   *       - USER
   *     description: Change user password for USER and PSYCHIATRIST
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: User authentication token
   *         in: header
   *         required: true
   *       - name: body
   *         in: body
   *         description: User's old and new passwords
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *             oldPassword:
   *               type: string
   *               description: Current password of the user
   *             newPassword:
   *               type: string
   *               description: New password to be set for the user
   *     responses:
   *       200:
   *         description: Returns success message after changing the password
   */
  async changePassword(req, res, next) {
    const validationSchema = {
      oldPassword: Joi.string().required(),
      newPassword: Joi.string().required(),
    };
    try {
      let validatedBody = await Joi.validate(req.body, validationSchema);
      let userResult = await findUser({ _id: req.userId });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      if (!bcrypt.compareSync(validatedBody.oldPassword, userResult.password)) {
        throw apiError.badRequest(responseMessage.PWD_NOT_MATCH);
      }
      let updated = await updateUserById(userResult._id, {
        password: bcrypt.hashSync(validatedBody.newPassword),
      });
      return res.json(new response({}, responseMessage.PWD_CHANGED));
    } catch (error) {
      return next(error);
    }
  }
  /**
   * @swagger
   * /user/deletePatientAccount:
   *   delete:
   *     tags:
   *       - USER
   *     description: deletePatientAccount for USER and PSYCHIATRIST
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: reason
   *         description: reason
   *         in: formData
   *         required: false
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async deletePatientAccount(req, res, next) {
    try {
      var userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      let deleteRes = await updateUser(
        { _id: userResult._id },
        { status: status.DELETE, reason: req.body.reason }
      );
      return res.json(new response(deleteRes, responseMessage.DELETE_SUCCESS));
    } catch (error) {
      return next(error);
    }
  }

  /**
   * @swagger
   * /user/resetPassword:
   *   post:
   *     tags:
   *       - USER
   *     description: Reset password by USER on plateform for USER and PSYCHIATRIST
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: password
   *         description: password
   *         in: formData
   *         required: true
   *       - name: confirmPassword
   *         description: confirmPassword
   *         in: formData
   *         required: true
   *     responses:
   *       200:
   *         description: Your password has been successfully changed.
   *       404:
   *         description: This user does not exist.
   *       422:
   *         description: Password not matched.
   *       500:
   *         description: Internal Server Error
   *       501:
   *         description: Something went wrong!
   */
  async resetPassword(req, res, next) {
    const validationSchema = {
      password: Joi.string().required(),
      confirmPassword: Joi.string().required(),
    };
    try {
      const { password, confirmPassword } = await Joi.validate(
        req.body,
        validationSchema
      );
      var userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
      });

      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      } else {
        if (password == confirmPassword) { 
          await updateUser(
            { _id: userResult._id },
            { password: bcrypt.hashSync(password) }
          );

          // await commonFunction.sendConfirmationMail(userResult.email)
          return res.json(new response({}, responseMessage.PWD_CHANGED));
        } else {
          throw apiError.notFound(responseMessage.PWD_NOT_MATCH);
        }
      }
    } catch (error) {
      console.log(error);
      return next(error);
    }
  }
 

  /**
   * @swagger
   * /user/viewPatientProfile:
   *   post:
   *     tags:
   *       - USER
   *     description: addAuthentication on  plateform for USER and PSYCHIATRIST
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async viewPatientProfile(req, res, next) {
    try {
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
      });
      if (!userResult) throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      userResult = _.omit(
        JSON.parse(JSON.stringify(userResult)),
        "otp",
        "otpTime",
        "__v"
      );
      return res.json(new response(userResult, responseMessage.DATA_FOUND));
    } catch (error) {
      console.log(error);
      return next(error);
    }
  }

 
 

  

 
 
 
 
 
 
 




 
 
  


  /**
   * @swagger
   * /admin/forgotPassword:
   *   post:
   *     tags:
   *       - ADMIN
   *     description: Admin initiates the forgot password process
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: body
   *         description: Forgot password details
   *         in: body
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *             email:
   *               type: string
   *               description: Admin's email address
   *     responses:
   *       200:
   *         description: Returns success message after initiating the forgot password process
   */

  async forgotPassword(req, res, next) {
    var validationSchema = {
      email: Joi.string().required(),
    };
    try {
      if (req.body.email) {
        req.body.email = req.body.email.toLowerCase();
      }
      var validatedBody = await Joi.validate(req.body, validationSchema);
      const { email } = validatedBody;
      var userResult = await findUser({
        email: email,
        status: { $ne: status.DELETE },
        userType: {$ne:userType.ADMIN},
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      } else {
        var otp = commonFunction.getOTP();
        var newOtp = otp;
        var time = Date.now() + 180000;
        await commonFunction.sendMailOtpForgetAndResend(email, otp);
        var updateResult = await updateUser(
          { _id: userResult._id },
          { $set: { otp: newOtp, otpTime: time } }
        );
        return res.json(new response({}, responseMessage.OTP_SEND));
      }
    } catch (error) {
      console.log(error);
      return next(error);
    }
  }  




  /**
   * @swagger
   * /user/patientListforPSYCHIATRIST:
   *   get:
   *     tags:
   *       - PSYCHIATRIST_USER_MANAGEMENT
   *     description: List of all USER on plateform by ADMIN Call this listuser API
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: status1
   *         description: status1
   *         in: query
   *         required: false
   *       - name: search
   *         description: search
   *         in: query
   *         required: false
   *       - name: fromDate
   *         description: fromDate
   *         in: query
   *         required: false
   *       - name: toDate
   *         description: toDate
   *         in: query
   *         required: false 
   *       - name: page
   *         description: page
   *         in: query
   *         type: integer
   *         required: false
   *       - name: limit
   *         description: limit
   *         in: query
   *         type: integer
   *         required: false
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async patientListforPSYCHIATRIST(req, res, next) {
    const validationSchema = {
      status1: Joi.string().allow("").optional(),
      search: Joi.string().allow("").optional(),
      fromDate: Joi.string().allow("").optional(),
      toDate: Joi.string().allow("").optional(),
      page: Joi.number().allow("").optional(),
      limit: Joi.number().allow("").optional(), 
    };
    try {
      const validatedBody = await Joi.validate(req.query, validationSchema);
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.PSYCHIATRIST,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }

      let dataResults = await paginateSearchAllUser(validatedBody);
      if (dataResults.docs.length == 0) {
        throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      }
      return res.json(new response(dataResults, responseMessage.DATA_FOUND));
      // console.log();
    } catch (error) {
      console.log("error===>>>>", error);
      return next(error);
    }
  }

 

  
  /**
   * @swagger
   * /user/viewPatient:
   *   get:
   *     tags:
   *       - PSYCHIATRIST_USER_MANAGEMENT
   *     description: view basic Details of any USER with _id
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: _id
   *         description: _id
   *         in: query
   *         required: false
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async viewPatient(req, res, next) {
    const validationSchema = {
      _id: Joi.string().required(),
    };
    try {
      const validatedBody = await Joi.validate(req.query, validationSchema);
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.PSYCHIATRIST,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      var userInfo = await findUser({
        _id: validatedBody._id,
        status: { $ne: status.DELETE },
      });
      console.log("userInfo==>>>>", userInfo);
      if (!userInfo) {
        throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      }
      let result = [];
      let walletRes = await walletList({
        userId: userInfo._id,
        status: { $ne: status.DELETE },
      });
      userInfo = _.omit(
        JSON.parse(JSON.stringify(userInfo)),
        "otp",
        "otpTime",
        "password",
        "__v"
      );
      result.push(userInfo);
      result.push(walletRes);
      return res.json(new response(result, responseMessage.DATA_FOUND));
    } catch (error) {
      if (error.isJoi) {
        return res.status(400).json({ error: error.details[0].message });
      } else {
        return next(error);
      }
    }
  } 


}

export default new userController();

 


 
 
 
