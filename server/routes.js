//v7 imports
import user from "./api/v1/controllers/user/routes"; 
import admin from './api/v1/controllers/admin/routes';
import statics from './api/v1/controllers/static/routes'; 



/**
 *
 *
 * @export
 * @param {any} app
 */

export default function routes(app) {

  app.use("/api/v1/user", user) 
  app.use('/api/v1/admin', admin)
  app.use('/api/v1/static', statics)  

  



  return app;
}
