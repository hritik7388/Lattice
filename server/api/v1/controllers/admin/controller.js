import Joi from "joi";
import _ from "lodash"; 
const axios = require("axios"); 
import userModel from "../../../../models/user.js";
import User from '../../../../models/user.js' 
import apiError from "../../../../helper/apiError";
import response from "../../../../../assets/response";
import bcrypt from "bcryptjs";
import responseMessage from "../../../../../assets/responseMessage";
import commonFunction from "../../../../helper/util";
import status from "../../../../enums/status";
import userType, { PSYCHIATRIST } from "../../../../enums/userType";  
import dotenv from "dotenv";
dotenv.config(); 
// ******************* Importing services *************************************//
import { userServices } from "../../services/user";  
import fs from "fs";   
const {
  checkUserExists,
  allactiveUser,
  createUser,
  findUser,
  userFindList,
  deleteUser,
  findfollowers,
  findfollowing,
  emailMobileExist,
  findUserData,
  updateUser,
  updateUserById,
  paginateSearch,
  paginateSearchAdmin,
  paginateSearchUser,
  userPsychiatristsList,
  userAllDetails,
  findCount,
  aggregateSearchUser,
} = userServices;
 
 
 
//******************************************************************************/

export class adminController {
  /**
   * @swagger
   * /admin/login:
   *   post:
   *     tags:
   *       - ADMIN
   *     description: Admin login with email and Password
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: login
   *         description: login
   *         in: body
   *         required: true
   *         schema:
   *           $ref: '#/definitions/Adminlogin'
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async login(req, res, next) {
    var validationSchema = {
      email: Joi.string().required(),
      password: Joi.string().required(), 
    };
    try {
      if (req.body.email) {
        req.body.email = req.body.email.toLowerCase();
      }
      var results;
      var validatedBody = await Joi.validate(req.body, validationSchema);
      const { email, password } = validatedBody;
      let userResult = await findUser({
        email: email,
        userType: { $in: [userType.ADMIN, userType.SUB_ADMIN] },
        status: { $ne: status.DELETE },
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      if (!bcrypt.compareSync(password, userResult.password)) {
        throw apiError.conflict(responseMessage.INCORRECT_LOGIN);
      } else {
        var token = await commonFunction.getToken({
          _id: userResult._id,
          email: userResult.email,
          mobileNumber: userResult.mobileNumber,
          userType: userResult.userType,
        });
        results = {
          _id: userResult._id,
          email: email,
          speakeasy: userResult.speakeasy,
          userType: userResult.userType,
          token: token,
        };
      }
      return res.json(new response(results, responseMessage.LOGIN));
    } catch (error) {
      console.log(error);
      return next(error);
    }
  }

 

  /**
   * @swagger
   * /admin/updateAdminProfile:
   *   put:
   *     tags:
   *       - ADMIN
   *     description: updateAdminProfile with all basic details he Want to update in future
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: email
   *         description: email
   *         in: formData
   *         required: false
   *       - name: firstName
   *         description: firstName
   *         in: formData
   *         required: false
   *       - name: lastName
   *         description: lastName
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
   *       - name: profilePic
   *         description: profilePic
   *         in: formData
   *         required: false
   *       - name: address
   *         description: address
   *         in: formData
   *         required: false
   *       - name: city
   *         description: city
   *         in: formData
   *         required: false
   *       - name: country
   *         description: country
   *         in: formData
   *         required: false
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async updateAdminProfile(req, res, next) {
    const validationSchema = {
      firstName: Joi.string().allow("").optional(),
      lastName: Joi.string().allow("").optional(),
      email: Joi.string().allow("").optional(),
      countryCode: Joi.string().allow("").optional(),
      mobileNumber: Joi.string().allow("").optional(),
      profilePic: Joi.string().allow("").optional(),
      address: Joi.string().allow("").optional(), 
      country: Joi.string().allow("").optional(),
    };
    try {
      console.log("gdgdjgdjdg");
      if (req.body.email) {
        req.body.email = req.body.email.toLowerCase();
      }
      let validatedBody = await Joi.validate(req.body, validationSchema);

      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      if (validatedBody.profilePic) {
        validatedBody.profilePic = validatedBody.profilePic;
        // validatedBody.profilePic = await commonFunction.getSecureUrl(validatedBody.profilePic);
      }
      if (validatedBody.mobileNumber) {
        let uniqueCheck = await findUser({
          mobileNumber: validatedBody.mobileNumber,
          _id: { $ne: userResult._id },
          status: { $ne: status.DELETE },
        });
        if (uniqueCheck) {
          throw apiError.conflict(responseMessage.MOBILE_EXIST);
        }
      }
      await updateUser({ _id: userResult._id }, validatedBody);
      return res.json(new response({}, responseMessage.PROFILE_UPDATED));
    } catch (error) {
      console.log("error", error);
      return next(error);
    }
  }
 

  /**
   * @swagger
   * /admin/verifyOTP:
   *   post:
   *     tags:
   *       - ADMIN
   *     description: Verify OTP by an admin for password reset
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: body
   *         description: OTP verification details
   *         in: body
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *             email:
   *               type: string
   *               description: Admin's email
   *             otp:
   *               type: integer
   *               description: OTP (One-Time Password) for verification
   *     responses:
   *       200:
   *         description: Returns user details and authentication token upon successful OTP verification
   */

  async verifyOTP(req, res, next) {
    var validationSchema = {
      email: Joi.string().required(),
      otp: Joi.number().required(),
    };
    try {
      if (req.body.email) {
        req.body.email = req.body.email.toLowerCase();
      }
      var validatedBody = await Joi.validate(req.body, validationSchema);
      const { email, otp } = validatedBody;
      var userResult = await findUserData({
        email: email,
        status: { $ne: status.DELETE },
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      if (new Date().getTime() > userResult.otpTime) {
        throw apiError.badRequest(responseMessage.OTP_EXPIRED);
      }
      if (userResult.otp != otp) {
        throw apiError.badRequest(responseMessage.INCORRECT_OTP);
      }
      var updateResult = await updateUser(
        { _id: userResult._id },
        { accountVerify: true }
      );
      var token = await commonFunction.getToken({
        id: updateResult._id,
        email: updateResult.email,
        mobileNumber: updateResult.mobileNumber,
        userType: updateResult.userType,
      });
      var obj = {
        _id: updateResult._id,
        email: updateResult.email,
        token: token,
      };
      return res.json(new response(obj, responseMessage.OTP_VERIFY));
    } catch (error) {
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
        userType: userType.ADMIN,
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
   * /admin/resetPassword:
   *   post:
   *     tags:
   *       - ADMIN
   *     description: Change password or reset password When ADMIN need to chnage
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
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      } else {
        if (password == confirmPassword) {
          let update = await updateUser(
            { _id: userResult._id },
            { password: bcrypt.hashSync(password) }
          );
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
   * /admin/resendOTP:
   *   put:
   *     tags:
   *       - ADMIN
   *     description: after OTP expire or not get any OTP with that frameOfTime ADMIN resendOTP for new OTP
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: resendOTP
   *         description: resendOTP
   *         in: body
   *         required: true
   *         schema:
   *           type: object
   *           properties:
   *              email:
   *                type: string
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async resendOTP(req, res, next) {
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
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      var otp = commonFunction.getOTP();
      var otpTime = new Date().getTime() + 180000;
      await commonFunction.sendMailOtpForgetAndResend(email, otp);
      // await commonFunction.sendMailOtpForgetAndResend(email, otp);
      var updateResult = await updateUser(
        { _id: userResult._id },
        { otp: otp, otpTime: otpTime }
      );
      return res.json(new response({}, responseMessage.OTP_SEND));
    } catch (error) {
      console.log(error.message);
      return next(error);
    }
  }

  /**
   * @swagger
   * /admin/changePassword:
   *   patch:
   *     tags:
   *       - ADMIN
   *     description: changePassword By ADMIN when ADMIN want to change his password on Plateform
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: changePassword
   *         description: changePassword
   *         in: body
   *         required: true
   *         schema:
   *           $ref: '#/definitions/changePassword'
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async changePassword(req, res, next) {
    const validationSchema = {
      oldPassword: Joi.string().required(),
      newPassword: Joi.string().required(),
    };
    try {
      let validatedBody = await Joi.validate(req.body, validationSchema);
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
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
   * /admin/adminProfile:
   *   get:
   *     tags:
   *       - ADMIN
   *     description: get his own profile details with adminProfile API
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
  async adminProfile(req, res, next) {
    try {
      let adminResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
      if (!adminResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      adminResult = _.omit(
        JSON.parse(JSON.stringify(adminResult)),
        "otp",
        "otpTime",
        "password",
        "__v"
      );

      return res.json(new response(adminResult, responseMessage.USER_DETAILS));
    } catch (error) {
      return next(error);
    }
  }
 
 
 
 
  //*************USER MANAGEMENT*****************/

  /**
   * @swagger
   * /admin/viewPatient:
   *   get:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
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
        userType: userType.ADMIN,
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

  /**
   * @swagger
   * /admin/deletePatient:
   *   delete:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
   *     description: deletePatient When Admin want to delete Any USER from plateform
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: deleteUser
   *         description: deleteUser
   *         in: body
   *         required: true
   *         schema:
   *           $ref: '#/definitions/deleteUser'
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async deletePatient(req, res, next) {
    const validationSchema = {
      _id: Joi.string().required(),
    };
    try {
      const validatedBody = await Joi.validate(req.body, validationSchema);
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      var userInfo = await findUser({
        _id: validatedBody._id,
        userType: { $ne: "ADMIN" },
        status: { $ne: status.DELETE },
      });
      if (!userInfo) {
        throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      }
      let deleteRes = await updateUser(
        { _id: userInfo._id },
        { status: status.DELETE }
      );
      return res.json(new response({}, responseMessage.DELETE_SUCCESS));
    } catch (error) {
      return next(error);
    }
  }

  /**
   * @swagger
   * /admin/blockUnblockPatient:
   *   put:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
   *     description: blockUnblockUser When ADMIN want to block User or Unblock USER on Plateform
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: blockUnblockUser
   *         description: blockUnblockUser
   *         in: body
   *         required: true
   *         schema:
   *           $ref: '#/definitions/blockUnblockUser'
   *     responses:
   *       200:
   *         description: Returns success message
   */
  async blockUnblockPatient(req, res, next) {
    const validationSchema = {
      _id: Joi.string().required(),
    };
    try {
      const validatedBody = await Joi.validate(req.body, validationSchema);
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      var userInfo = await findUser({
        _id: validatedBody._id,
        userType: { $ne: "ADMIN" },
        status: { $ne: status.DELETE },
      });
      if (!userInfo) {
        throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      }
      if (userInfo.status == status.ACTIVE) {
        let blockRes = await updateUser(
          { _id: userInfo._id },
          { status: status.BLOCK }
        );
        let senderNotificationObj = {
          userId: userInfo._id,
          type: "NOTIFICATION",
          title: "Account Blocked",
          message: "Your Account has been blocked by admin !",
        };
        await notificationCreate(senderNotificationObj);
        return res.json(new response({}, responseMessage.BLOCK_BY_ADMIN));
      } else {
        let activeRes = await updateUser(
          { _id: userInfo._id },
          { status: status.ACTIVE }
        );
        let senderNotificationObj = {
          userId: userInfo._id,
          type: "NOTIFICATION",
          title: "Account Unblocked",
          message: "Your Account has been Unblocked by admin !",
        };
        await notificationCreate(senderNotificationObj);
        return res.json(new response({}, responseMessage.UNBLOCK_BY_ADMIN));
      }
    } catch (error) {
      return next(error);
    }
  }
 

  /**
   * @swagger
   * /admin/listPatient:
   *   get:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
   *     description: List of all listPatient on plateform by ADMIN Call this listuser API
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
  async listPatient(req, res, next) {
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
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }

      let dataResults = await paginateSearch(validatedBody);
      if (dataResults.docs.length == 0) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      return res.json(new response(dataResults, responseMessage.DATA_FOUND));
      console.log();
    } catch (error) {
      console.log("error===>>>>", error);
      return next(error);
    }
  }
  /**
   * @swagger
   * /admin/patientList:
   *   get:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
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
  async patientList(req, res, next) {
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
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }

      let dataResults = await paginateSearchUser(validatedBody);
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
  * /admin/getPatientPSYCHIATRISTRanking:
  *   get:
  *     tags:
  *       - ADMIN
  *     description: getPatientPSYCHIATRISTRanking
  *     produces:
  *       - application/json
  *     parameters:
  *       - name: token
  *         description: token
  *         in: header
  *         required: true
  *       - name: page
  *         description: page
  *         in: query
  *         required: false
  *       - name: limit
  *         description: limit
  *         in: query
  *         required: false
  *     responses:
  *       200:
  *         description: Returns success message
  */
 async getPatientPSYCHIATRISTRanking(req, res, next) {
   try {
     const { page = 1, limit = 10 } = req.query;
     const pageNumber = parseInt(page);
     const limitNumber = parseInt(limit);

     if (
       isNaN(pageNumber) ||
       isNaN(limitNumber) ||
       pageNumber < 1 ||
       limitNumber < 1
     ) {
       throw apiError.badRequest("Invalid page or limit parameters");
     }

     let userResult = await findUser({
       _id: req.userId,
       status: { $ne: status.DELETE },
       userType: { $ne: userType.USER },
     });
     if (!userResult) {
       throw apiError.notFound(responseMessage.USER_NOT_FOUND);
     }

     const pipeline = [
      {
        $unwind: {
          path: "$psychiatristsId",
        },
      },
      {
        $group: {
          _id: "$psychiatristsId",
          count: {
            $sum: 1,
          },
        },
      },
      {
        $sort: { count: -1 }, // Sort by count in descending order
      },
      {
        $sort: { count: -1 }, // Sort again by count in descending order
      },
    ];

     const referralCounts = await User.aggregate(pipeline);
      

     if (!referralCounts || referralCounts.length === 0) {
       throw apiError.notFound("No referral counts found");
     }

     const startIndex = (pageNumber - 1) * limitNumber;
     const endIndex = startIndex + limitNumber;
     const paginatedReferralCounts = referralCounts.slice(
       startIndex,
       endIndex
     );

     let userData = [];
     let totalUserCount = 0;

     for (let referral of paginatedReferralCounts) {
       let userdocs = await User.find({ _id: referral._id ,psychiatristsId:referral.psychiatristsId});
       console.log("userdocs==========>>>>>>>",referral)
       console.log("paginatedReferralCounts=======>>>>>",paginatedReferralCounts)
       console.log("userdocs======>>>>",userdocs)

       if (userdocs.length > 0) {
         totalUserCount += userdocs.length;
         let data = {
           DRname: userdocs[0].fullName,
           Dr_id: userdocs[0]._id, 
           patientsCount: referral.count,
         };
         console.log("userId==========",data.userId)

         userData.push(data);
       } else {
         //console.log(`No user found with referralCode: ${referral._id}`);
       }
     }

     //console.log("userDatauserDatauserDatauserData", userData);

     return res.status(200).json({
       responseCode: 200,
       responseMessage: "PsychiatristsId counts found successfully",
       referralData: userData,
       page: pageNumber,
       totalPages: Math.ceil(referralCounts.length / limitNumber),
       totalUserCount,
     });
   } catch (error) {
     console.log("getUserUniqueReferal error:", error);
     return next(error);
   }
 }
 
 

  /**
   * @swagger
   * /admin/getAllPatient:
   *   get:
   *     tags:
   *       - ADMIN
   *     description: getAllUser by ADMIN
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
  async getAllPatient(req, res, next) {
    try {
      const adminResult = await findUser({
        _id: req.userId,
        userType: userType.ADMIN,
      });
      if (!adminResult) {
        throw apiError.unauthorized(responseMessage.UNAUTHORIZED);
      }
      let getAllUser = await userModel.find();
      return res.status(200).json({ responseCode: 200, responseMessage: "Get USER successfully" });
    } catch (error) {
      console.log("getCashCollectionList==>>>", error);
      return next(error);
    }
  }

   
 




  /**
   * @swagger
   * /admin/listPSYCHIATRIST:
   *   get:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
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
  async listPSYCHIATRIST(req, res, next) {
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
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }

      let dataResults = await userPsychiatristsList(validatedBody);
      if (dataResults.docs.length == 0) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      return res.json(new response(dataResults, responseMessage.DATA_FOUND));
      console.log();
    } catch (error) {
      console.log("error===>>>>", error);
      return next(error);
    }
  }



  
  /**
   * @swagger
   * /admin/countPsychiatrist:
   *   get:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
   *     description: countPsychiatrist
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
  async countPsychiatrist(req,res){
    try { 
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }

      const results = await userModel.aggregate([
        {
          $match: { userType: userType.PSYCHIATRIST }
      },
      {
          $group: {
              _id: "$hospital", // Grouping by hospital
              count: { $sum: 1 } // Counting psychiatrists in each hospital
          }
      },
      {
          $sort: { count: -1 } // Sort by count in descending order
      },
      {
          $project: {
              _id: 0,
              hospital: "$_id",
              count: 1
          }
      }
  ]);
    
    
      return res.json(new response(results, responseMessage.DATA_FOUND)); 
    } catch (error) {
      console.log("error===>>>>", error); 
    }
  }




   /**
   * @swagger
   * /admin/countPatient:
   *   get:
   *     tags:
   *       - ADMIN_USER_MANAGEMENT
   *     description: countPatient
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
   async countPatient(req,res){
    try { 
      let userResult = await findUser({
        _id: req.userId,
        status: { $ne: status.DELETE },
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }

      let dataResults = await userModel.count({userType:userType.USER})
    
      return res.json(new response(dataResults, responseMessage.DATA_FOUND)); 
    } catch (error) {
      console.log("error===>>>>", error); 
    }
  } 

}
export default new adminController();

 
 

 