require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

// Models
const User = require('./models/User')

app.get('/test', (req, res) => {
  return res.json({ msg: 'Bem vindo a nossa API' })
})

// Middlewares
function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) return res.status(401).json({ msg: 'acesso negado' })

  try {
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()
  } catch (err) {
    return res.status(400).json({ msg: 'token inválido' })
  }
}

// Private route
app.get('/user/:id', checkToken, async (req, res) => {
  const id = req.params.id

  // check if user exists
  const user = await User.findById(id, '-password')

  if (!user) return res.status(404).json({ msg: 'usuário não encontrado' })
  return res.json({ user })
})

// Register user
app.post('/auth/register', async (req, res) => {
  const {
    name,
    email,
    password,
    confirm_password
  } = req.body

  // validations
  if (!name) return res.status(422).json({ msg: 'O nome é obrigatório' })

  if (!email) return res.status(422).json({ msg: 'O email é obrigatório' })

  if (!password) return res.status(422).json({ msg: 'A senha é obrigatória' })

  if (password !== confirm_password) return res.status(422).json({ msg: 'As senhas são diferentes' })

  // check if user already exists
  const userAlreadyExists = await User.findOne({ email: email })

  if (userAlreadyExists) return res.status(422).json({ msg: 'email já cadastrado' })

  // create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // create user
  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {
    await user.save()
    return res.status(201).json({ msg: 'Usuário criado com sucesso' })
  } catch (err) {
    return res.status(500).json({ msg: err })
  }
})

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  // validations
  if (!email) return res.status(422).json({ msg: 'O email é obrigatório' })

  if (!password) return res.status(422).json({ msg: 'A senha é obrigatória' })

  // check if user already exists
  const user = await User.findOne({ email: email })

  if (!user) return res.status(404).json({ msg: 'usuário não encontrado' })

  // check if password match
  const checkPass = await bcrypt.compare(password, user.password)

  if (!checkPass) return res.status(422).json({ msg: 'senha inválida' })

  try {
    const secret = process.env.SECRET
    const token = jwt.sign({ id: user._id }, secret)

    return res.json({
      msg: 'sucesso',
      token
    })
  } catch (error) {
    return res.status(500).json({ msg: err })
  }
})

const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@joao-dev.ckap7.mongodb.net/mongodbJWTAuthentication?retryWrites=true&w=majority`)
  .then(() => app.listen(3333))
  .catch(err => console.log(err))
