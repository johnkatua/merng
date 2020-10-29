const { Authentication, AuthenticationError } = require('apollo-server');
const dotenv = require('dotenv')
dotenv.config()

const jwt = require('jsonwebtoken');
//const { SECRET_KEY } = require('../config');

const {SECRET_KEY} =  process.env

module.exports = (context) => {
  const authHeader = context.req.headers.authorization;
  if(authHeader) {
    const token = authHeader.split('Bearer ')[1];
    if(token) {
      try{
        const user = jwt.verify(token, SECRET_KEY);
        return user;
      } catch(err) {
        throw new AuthenticationError('Invalid/Expired token')
      }
    }
    throw new Error("Authentication token must be 'Bearer[token]'");
  }
  throw new Error('Authorization header must be provided');
}