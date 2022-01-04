var express = require('express');
var router = express.Router();
const jwt = require('jsonwebtoken');
const jwtKey = 'thisisjwtkey';
let role;

const verifyRoleFromToken = async (req, res, next) => {
  const token = req.cookies.token;
  const decodedToken = jwt.verify(token, jwtKey);
  if (decodedToken.role === 'member') {
    role = 'member';
    next();
  } else if (decodedToken.role === 'admin') {
    role = 'admin';
    next();
  } else {
    res.json({msg: 'Authorization fail!'});
  }
}

const verifyRoleMember = async (req, res, next) => {
  if (role === 'member') {
    next();
  } else {
    res.status(401)
    res.json({msg: 'Not member'});
  }
}

const verifyRoleAdmin = async (req, res, next) => {
  if (role === 'admin') {
    next();
  } else {
    res.status(401)
    res.json({msg: 'Not admin'});
  }
}

router.use(verifyRoleFromToken);

router.get('/member', verifyRoleMember, async (req, res, next)=> {
  res.json({msg: role});
});

router.get('/admin', verifyRoleAdmin, async (req, res, next)=> {
  res.json({msg: role});
});

module.exports = router;
