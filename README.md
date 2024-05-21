# lattice


# Fithun Application

## Getting Started

### Prerequisites

1. Node.js (v16.0.0 or Above)
2. npm i

## Installation

1. Run `npm i` in your terminal to install all dependencies.
2. Run `node index.js` or `nodemon` in your terminal to run the local server.

## Environment Variables

Ensure you fill in the respective values for each environment variable in your `.env` file.

```dotenv
port=2001
hostAddress=localhost:2001
databasePort=27017
databaseName=Apollo_Hospital
databaseHostLocal=127.0.0.1
databaseHost=planetspark
dbUserName=Apollo_Hospital 
jwtsecret=nodejwt
jwtresetsecret=nodejwt

nodemailer_service=gmail
nodemailer_email=Your 2 step verification credential
nodemailer_password=Your 2 step verification credential

jwtOptions_expiresIn=24h

swaggerDefinition_info_title=planetspark-node
swaggerDefinition_info_version=2.0
swaggerDefinition_info_description=planetspark-API Docs
swaggerDefinition_basePath=/api/v1
swaggerDefinition_securityDefinitions_tokenauth_type=apiKey
swaggerDefinition_securityDefinitions_tokenauth_name=Authorization
swaggerDefinition_securityDefinitions_tokenauth_in=header 

also  according to the assingment i have completed all the auth field for user and all the api you want to fetch the Psychiatrist Details (the name of api is /admin/getPatientPSYCHIATRISTRanking)
and also count of the patiend and PSYCHIATRIST