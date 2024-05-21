import Express from "express";
import controller from "./controller";
import auth from "../../../../helper/auth";
import upload from "../../../../helper/uploadHandler";

export default Express.Router()
  .use(upload.uploadFile)
  .post("/login", controller.login) 
  .post("/forgotPassword", controller.forgotPassword)
  .post("/verifyOTP", controller.verifyOTP)
  .put("/resendOTP", controller.resendOTP) 
  .use(auth.verifyToken)  
  .patch("/changePassword", controller.changePassword)
  .get("/adminProfile", controller.adminProfile) 
  .post("/resetPassword", controller.resetPassword) 
  .put("/updateAdminProfile", controller.updateAdminProfile)  
  // ************ADMIN USER NAMAGEMENT***********************/
  .get("/viewPatient", controller.viewPatient)
  .delete("/deletePatient", controller.deletePatient)
  .put("/blockUnblockPatient", controller.blockUnblockPatient) 
  .get("/listPatient", controller.listPatient)
  .get("/patientList", controller.patientList)   
  .put("/updateAdminProfile", controller.updateAdminProfile) 
  .get("/getPatientPSYCHIATRISTRanking",controller.getPatientPSYCHIATRISTRanking) 
  .get("/listPSYCHIATRIST",controller.listPSYCHIATRIST)
  .get("/countPsychiatrist",controller.countPsychiatrist)
  .get("/countPatient",controller.countPatient)
  .get("/getAllPatient",controller.getAllPatient)

