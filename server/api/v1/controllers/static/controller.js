import Joi from "joi";
import _ from "lodash";
import apiError from "../../../../helper/apiError";
import response from "../../../../../assets/response";
import responseMessage from "../../../../../assets/responseMessage";
import commonFunction from "../../../../helper/util";
import fs from "fs";
import pdf from "pdf-parse";

import { staticServices } from "../../services/static";
const {
  createStaticContent,
  findStaticContent,
  updateStaticContent,
  staticContentList,
} = staticServices; 
  

import { userServices } from "../../services/user";
const { findUser } = userServices;
import status from "../../../../enums/status";
import userType from "../../../../enums/userType";
import { ConversationList } from "twilio/lib/rest/conversations/v1/conversation";

export class staticController {
  //**************************  Static management Start *************************************************/
  /**
   * @swagger
   * /static/addStaticContent:
   *   post:
   *     tags:
   *       - STATIC
   *     description: addStaticContent
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: admin token
   *         in: header
   *         required: true
   *       - name: file
   *         description: pdf file to add static content.
   *         in: formData
   *         type: file
   *         required: true
   *     responses:
   *       200:
   *         description: Returns success message
   */

  async addStaticContent(req, res, next) {

    try {

      console.log("🚀 ~ staticController ~ addStaticContent ~ req.files[0].path:", req.files[0].path)
      let imgUrl1 = await commonFunction.getImageUrl(req.files);
      const pdfFilePath = req.files[0].path;
      const dataBuffer = fs.readFileSync(pdfFilePath);
      const data = await pdf(dataBuffer);
      const textContent = data.text;
      const typePattern = /type:(.*)/i;
      const titlePattern = /title:(.*)/i;
      const descriptionPattern = /description:(.*)/i;
      const parsedData = {};
      const typeMatch = textContent.match(typePattern);
      const titleMatch = textContent.match(titlePattern);
      const descriptionMatch = textContent.match(descriptionPattern);
      if (typeMatch) {
        parsedData.type = typeMatch[1].trim();
      }
      if (titleMatch) {
        parsedData.title = titleMatch[1].trim();
      }
      if (descriptionMatch) {
        parsedData.description = descriptionMatch[1].trim();
      }
      const staticDataAdeed = await createStaticContent(parsedData);
      console.log("🚀 ~ staticController ~ addStaticContent ~ imgUrl1:", parsedData)
      if(staticDataAdeed){
        return res.status(200).json({staticDataAdeed, responseCode: 200, responseMessage: "static Data added successfully" });
      }
    } catch (error) {
      console.log("🚀 ~ staticController ~ addStaticContent ~ error:", error)
      return next(error);
    }
  }

  /**
   * @swagger
   * /static/viewStaticContent:
   *   get:
   *     tags:
   *       - STATIC
   *     description: viewStaticContent
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: type
   *         description: type
   *         in: query
   *         required: true
   *     responses:
   *       200:
   *         description: Returns success message
   */

  async viewStaticContent(req, res, next) {
    const validationSchema = {
      type: Joi.string().required(),
    };
    try {
      const validatedBody = await Joi.validate(req.query, validationSchema);
      var result = await findStaticContent({ type: validatedBody.type });
      if (!result) throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      return res.json(new response(result, responseMessage.DATA_FOUND));
    } catch (error) {
      return next(error);
    }
  }

  /**
   * @swagger
   * /static/editStaticContent:
   *   put:
   *     tags:
   *       - STATIC
   *     description: editStaticContent
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: editStaticContent
   *         description: editStaticContent
   *         in: body
   *         required: true
   *         schema:
   *           $ref: '#/definitions/editStaticContent'
   *     responses:
   *       200:
   *         description: Returns success message
   */

  async editStaticContent(req, res, next) {
    const validationSchema = {
      _id: Joi.string().required(),
      title: Joi.string().optional(),
      description: Joi.string().optional(),
      url: Joi.string().optional(),
    };
    try {
      const validatedBody = await Joi.validate(req.body, validationSchema);
      let staticRes = await findStaticContent({ _id: req.body._id });
      if (!staticRes) throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      var result = await updateStaticContent(
        { _id: validatedBody._id },
        validatedBody
      );
      return res.json(new response(result, responseMessage.UPDATE_SUCCESS));
    } catch (error) {
      return next(error);
    }
  }

  /**
   * @swagger
   * /static/staticContentList:
   *   get:
   *     tags:
   *       - STATIC
   *     description: staticContentList
   *     produces:
   *       - application/json
   *     responses:
   *       200:
   *         description: Returns success message
   */

  async staticContentList(req, res, next) {
    try {
      var result = await staticContentList({ status: { $ne: status.DELETE } });
      return res.json(new response(result, responseMessage.DATA_FOUND));
    } catch (error) {
      return next(error);
    }
  }

  


 

  //**************************  FAQs management End *************************************************/

  /**
   * @swagger
   * /static/deleteStaticContent:
   *   delete:
   *     tags:
   *       - ADMIN STATIC MANAGEMENT
   *     description: deleteStaticContent
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: token
   *         description: token
   *         in: header
   *         required: true
   *       - name: staticId
   *         description: staticId
   *         in: formData
   *         required: true
   *     responses:
   *       200:
   *         description: Returns success message
   */

  async deleteStaticContent(req, res, next) {
    const validationSchema = {
      staticId: Joi.string().required(),
    };
    try {
      const validatedBody = await Joi.validate(req.body, validationSchema);
      let userResult = await findUser({
        _id: req.userId,
        userType: userType.ADMIN,
      });
      if (!userResult) {
        throw apiError.notFound(responseMessage.USER_NOT_FOUND);
      }
      var result = await findStaticContent({
        _id: validatedBody.staticId,
        status: { $ne: status.DELETE },
      });
      if (!result) {
        throw apiError.notFound(responseMessage.DATA_NOT_FOUND);
      }
      let updateRes = await updateStaticContent(
        { _id: result._id },
        { status: status.DELETE }
      );
      return res.json(new response(updateRes, responseMessage.DATA_FOUND));
    } catch (error) {
      return next(error);
    }
  }
}

export default new staticController();
