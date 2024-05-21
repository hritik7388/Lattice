import config from "config";
import jwt from "jsonwebtoken";
const fs = require("fs");
import fcm from "fcm-push"; 
import ses from "node-ses"; 

import cloudinary from "cloudinary";
import nodemailer from "nodemailer";

const accountSid = config.get("twilio.accountSid");
const authToken = config.get("twilio.authToken");
const client = require("twilio")(accountSid, authToken);

// cloudinary.config({
//   cloud_name: config.get('cloudinary.cloud_name'),
//   api_key: config.get('cloudinary.api_key'),
//   api_secret: config.get('cloudinary.api_secret')
// });

 

 
 

module.exports = {
  getOTP() {
    var otp = Math.floor(1000 + Math.random() * 9000);
    return otp;
  },

  genId() {
    var ID = Math.floor(10000000000 + Math.random() * 90000000000);
    return ID;
  },

  dateTime() {
    var today = new Date(
      new Date() - new Date().getTimezoneOffset() * 60 * 1000
    ).toISOString();
    var check = "";
    check = today.split(".")[0].split("T");
    var time = check[1].split(":")[0] > "11" ? " PM" : " AM";
    check = check[0].split("-").reverse().join("/") + " " + check[1] + time;
    return check;
  },

  makeReferral() {
    var result = "";
    var characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var charactersLength = characters.length;
    for (var i = 0; i < 6; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  },

  getToken: async (payload) => {
    var token = await jwt.sign(payload, config.get("jwtsecret"), {
      expiresIn: "12h",
    });
    return token;
  },

  sendMail: async (to, subject, body) => {
    const msg = {
      to: to, // Change to your recipient
      from: "no-replymailer@mobiloitte.com", // Change to your verified sender
      subject: subject,
      text: body,
    };
    sgMail
      .send(msg)
      .then((response) => {
        console.log(response[0].statusCode);
        console.log(response[0].headers);
      })
      .catch((error) => {
        console.error(error);
      });
  },



  getImageUrl: async (files) => {
    var mediaURL;
    var date = new Date().getTime();
    const fileContent = fs.readFileSync(files[0].path);
    const params = {
      Bucket: config.get("AWS.bucketName"),
      ContentType: files[0].mimetype,
      Key: `uploads/${date}${files[0].filename}`,
      Body: fileContent,
    };
    // console.log("util1119999999",params)
    // console.log("🚀 ~ getImageUrl: ~ params:", params)
    let data = await s3.upload(params).promise();
    console.log("1111199999=======>>>>>>>>", data)
    mediaURL = data.Location;
    return mediaURL;
  },
  getImageUrl2: async (url) => {
    var result = await cloudinary.v2.uploader.upload(url);
    console.log("82", result);
    return result.secure_url;
  },
  getImageUrl1: async (files) => {
    console.log("files: ", files)
    await cloudinary.config({
      cloud_name: config.get("cloudinary.cloud_name"),
      api_key: config.get("cloudinary.api_key"),
      api_secret: config.get("cloudinary.api_secret"),
    });

    var result = await cloudinary.v2.uploader.upload(files, {
      resource_type: "auto"
    });
    return result;
  },

  uploadToS3: async (base64) => {
    const buffer = Buffer.from(base64, 'base64');
    const params = {
      Bucket: config.get("AWS.bucketName"),
      ContentType: 'image/png',
      Key: `uploads/${Date.now()}/image.png`, // Replace with your desired key structure
      Body: buffer,
      // ACL: 'private' // Set the ACL as needed (private, public-read, etc.)
    };
    try {
      const result = await s3.upload(params).promise();
      console.log("result========================>>>", result.Location)
      return result.Location; // Return the URL of the uploaded image
    } catch (error) {
      console.error('Error uploading to S3:', error);
      throw error;
    }
  },

  // getImageUrl: async (files) => {
  //   var result = await cloudinary.v2.uploader.upload(files[0].path, { resource_type: "auto" })
  //   return result.secure_url;
  // },
  getSecureUrl: async (base64) => {
    var result = await cloudinary.v2.uploader.upload(base64, { resource_type: "auto" });
    return result.secure_url;
  },
  uploadImage(image) {
    return new Promise((resolve, reject) => {
      cloudinary.uploader.upload(image, function (error, result) {
        if (error) {
          reject(error);
        } else {
          console.log("result===>>", result.url);
          resolve(result.url);
        }
      });
    });
  },

  // sendSmsTwilio: async (mobileNumber, otp)=> {
  //   const message = `Your mobile One Time Password (OTP) to log in to your digital bank account is ${otp}. The OTP is valid for 3 minutes.`;
  //   const params = {
  //     Message: message,
  //     PhoneNumber: mobileNumber,
  //   }

  //   try {
  //     const response = await sns.publish(params).promise();
  //     console.log('SMS sent using AWS SNS:', response);
  //     return response;
  //   } catch (error) {
  //     console.error('Error sending SMS using AWS SNS:', error);
  //     throw error;
  //   }
  // },
  sendSmsTwilio: async (mobileNumber, otp) => {
    try {
      let sent = await client.messages.create({
        body: `Your mobile One Time Password (OTP) to log in to your digital bank account is ${otp}.The OTP is valid for 3 minutes.`,
        to: mobileNumber,
        from: config.get("twilio.number"),
      });
      console.log("1988888", sent)
    } catch (error) {
      console.log("160 ==>", error);
    }
  },
  randomString: (length) => {
    let result = '';
    let chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
  },
  //************************************ PUSH NOTIFICATIONS ************************************************************ */

  pushNotification: (deviceToken, subject, body, callback) => {
    var message = {
      to: deviceToken, // required fill with device token or topics
      content_available: true,
      notification: {
        subject: subject,
        // title: title,
        body: body,
      },
    };
    fcm.send(message, function (err, response) {
      if (err) {
        console.log("err", err);
        callback(err, null);
      } else {
        console.log("response", response);
        callback(null, response);
      }
    });
  },

  //  sendNotificationWithAttachment: async(deviceToken, messageTitle, messageBody) => {
  //   try {
  //     // Define the message payload
  //     const message = {
  //       notification: {
  //         title: messageTitle,
  //         body: messageBody,
  //       },
  //       data: {},
  //       token: deviceToken,
  //     };



  //     // Send the notification
  //     const response = await admin.messaging().send(message);
  //     console.log('Successfully sent notification:', response);
  //   } catch (error) {
  //     console.error('Error sending notification:', error);
  //   }
  // },


  // pushNotificationDelhi: (deviceToken, title, body, callback) => {
  //   var message = {
  //     to: deviceToken, // required fill with device token or topics
  //     content_available: true,
  //     notification: {
  //       title: title,
  //       body: body,
  //     },
  //     data: {
  //       title: title,
  //       body: body,
  //     },
  //   };
  //   fcm.send(message, function (err, response) {
  //     if (err) {
  //       console.log("err", err);
  //       callback(err, null);
  //     } else {
  //       console.log("response", response);
  //       callback(null, response);
  //     }
  //   });
  // },

  // ************************************ MAIL FUNCTIONALITY WITH NodeMailer *****************************************************/

  sendMailOtpForgetAndResend: async (email, otp) => {
    let html = mailTemplet.otpForgetResetTemplet(otp);
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Resend OTP",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },
  frozenUserSendMail: async (email) => {
    let html = mailTemplet.freezeUserTemplate();
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "User Freeze by Admin",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },
  sendMailForSubscriptionPurchase: async (email, subscriptionName) => {
    console.log("🚀 ~ sendMailForSubscriptionPurchase: ~ subscriptionName:", subscriptionName)
    let html;
    if (subscriptionName == "Standard") {
      html = mailTemplet.standardSubscriptionTemplate();
    } else if (subscriptionName == "Pro") {
      html = mailTemplet.proSubscriptionTemplate()
    } else if (subscriptionName == "Plus") {
      html = mailTemplet.plusSubscriptionTemplate()
    }
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Subscription Purchased successfully",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendMailOtpNodeMailer: async (email, otp) => {
    let html = mailTemplet.signUpTemplet(otp);
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Welcome to Rival - Email OTP Confirmation ",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendKycEmail: async (email, name) => {
    let html = mailTemplet.addKycTemplet(name);
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "KYC Submission Received",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },
  sendMailKYCapprove: async (email, body) => {
    let html = mailTemplet.mailKYCApproveTemplet(body);
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Successful KYC Verification ",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendPassConfirmationMail: async (email) => {
    let html = mailTemplet.sendPassConfirmationMailTemplet();
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Reset password Successful",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendConfirmationMail: async (email) => {
    let html = mailTemplet.sendConfirmationMailTemplet();
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Reset password Successful",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendMailKYCreject: async (email, body) => {
    let html = mailTemplet.mailKYCRejectTemplet(body);
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Failed KYC Verification ",
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendMailStakeReject: async (email, body) => {
    let html = mailTemplet.mailStakeRejectTemplet(body);
    let subject = "STAKE STATUS";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);

  },

  sendMailStakeAccept: async (email, body) => {
    let html = mailTemplet.mailStakeAcceptTemplet(body);
    let subject = "STAKE STATUS";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendMailExchangeReject: async (email, body) => {
    let html = mailTemplet.mailExchangeRejectTemplet(body);
    let subject = "EXCHANGE STATUS";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);

  },

  sendMailExchangeAccept: async (email, body) => {
    let html = mailTemplet.mailExchangeAcceptTemplet(body);
    let subject = "EXCHANGE STATUS";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },
  sendEmailLoginCredential: async (email, body) => {
    let html = mailTemplet.mailLoginCredentialTemplet(body);
    let subject = "ADMIN CREDENTIALS";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendEmailForDeposit: async (email, body) => {
    let html = mailTemplet.depositmailTemp(body);
    let subject = "Deposit Successful";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendEmailForWithdraw: async (email, body) => {
    let html = mailTemplet.withdrawMailTemp(body);
    let subject = "Withdrawal Successful";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: subject,
      html: html,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendEmailForSubscriptionExpiry: async (email, message) => {
    let text = "Your subscription is expired please renew again!";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Subscription Reminder",
      text: message,
    };
    return await transporter.sendMail(mailOptions);
  },

  sendEmailForAccountDisable: async (email, body) => {
    let text = "Your subscription is expired please renew again!";
    var transporter = nodemailer.createTransport({
      service: config.get("nodemailer.service"),
      auth: {
        user: config.get("nodemailer.email"),
        pass: config.get("nodemailer.password"),
      },
    });
    var mailOptions = {
      from: "<do_not_reply@gmail.com>",
      to: email,
      subject: "Subscription Reminder",
      text: text,
    };
    return await transporter.sendMail(mailOptions);
  },

};