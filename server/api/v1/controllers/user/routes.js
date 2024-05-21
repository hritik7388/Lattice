import Express from "express";
import controller from "./controller";
import auth from "../../../../helper/auth";
import upload from "../../../../helper/uploadHandler";

export default Express.Router()
  .use(upload.uploadFile) 

  // *********************USER*********************/

  .post("/signUp", controller.signUp) 




  .patch("/verifyOTP", controller.verifyOTP) 
  .post("/resendOTP", controller.resendOTP) 

  .post("/login", controller.login) 
  .post("/checkPatient", controller.checkPatient) 
  .post('/forgotPassword',controller.forgotPassword)   
  .use(auth.verifyToken)   
  .delete("/deletePatientAccount", controller.deletePatientAccount) 
  .post("/resetPassword", controller.resetPassword) 
  .patch("/changePassword", controller.changePassword)  
  .post("/viewPatientProfile", controller.viewPatientProfile)    
  .put("/editProfile", controller.editProfile)  
  .get("/patientListforPSYCHIATRIST",controller.patientListforPSYCHIATRIST) 
  .get("/viewPatient",controller.viewPatient)
