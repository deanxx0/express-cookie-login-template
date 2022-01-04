var express = require('express');
var router = express.Router();
const db = require('../db');
const usersCollection = db.collection('users');
const ObjectId = require('mongodb').ObjectId;
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const jwtKey = 'thisisjwtkey';

router.get('/verifytoken', async (req, res, next) => {
  // const token = req.body.token;
  const token = req.cookies.token;
  const decodedToken = jwt.verify(token, jwtKey);
  res.json(decodedToken);
})

router.post('/login', async (req, res, next)=>{
  const user = await usersCollection.findOne({username: req.body.username});
  if (!user) res.json({msg: 'no user'});
  const hashedPassword = user.password;
  const same = await bcrypt.compare(req.body.password, hashedPassword);
  if(!same) res.json({msg: 'wrong password'});
  const token = jwt.sign({
    username: user.username,
    role: user.role
  }, jwtKey, {expiresIn: '1h'});
  res.status(200);
  res.cookie('token', token, {
    maxAge: 900000,
    httpOnly: false,
    sameSite: "None",
    secure: true
  });
  res.json(token);
})

router.post('/', async (req, res, next) => {
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);
  const obj = {
    username: req.body.username,
    password: hashedPassword,
    role: 'member',
    createdAt: new Date(Date.now()),
    updatedAt: new Date(Date.now())
  }
  const result = await usersCollection.insertOne(obj);
  res.json(result);
});

router.get('/', async (req, res, next) =>{
  const result = await usersCollection.find().toArray();
  res.json(result);
});

router.get('/:id', async (req, res, next) => {
  const oid = new ObjectId(req.params.id);
  const result = await usersCollection.find({_id: oid}).toArray();
  res.json(result);
})

router.delete('/:id', async (req, res, next) => {
  const oid = new ObjectId(req.params.id);
  const result = await usersCollection.deleteOne({_id: oid});
  res.json(result);
})

router.put('/', async (req, res, next) => {
  const oid = new ObjectId(req.body._id);
  const findResult = await usersCollection.findOne({_id: oid});
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);
  const obj = {
    _id: oid,
    username: req.body.username,
    password: hashedPassword,
    role: req.body.role,
    createdAt: findResult.createdAt,
    updatedAt: new Date(Date.now())
  }
  const result = await usersCollection.replaceOne({_id: obj._id}, obj);
  res.json(result);
})

module.exports = router;
