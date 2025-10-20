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
const checkRole = role => (req, res, next) => {
  if (req.decodedJwt && req.decodedJwt.role === role) {
    next()
  }else {
    next({ status: 403, message: 'You are not authorized to access this resource' })
  }
}

module.exports = {
  restricted,
  checkRole,
}
