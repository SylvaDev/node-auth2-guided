const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../../config')

// AUTHENTICATION
const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: 'Token invalid' })
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  }else {
    next({ status: 401, message: 'Token required' })
  }
}

// AUTHORIZATION
const checkRole = (req, res, next) => {
  next()
}

module.exports = {
  restricted,
  checkRole,
}
