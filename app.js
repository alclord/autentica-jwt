//Imports
require('dotenv').config()
const express = require('express')
const moongose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//config json response
app.use(express.json())
//models
const User = require('./models/Users')

//Open Route - Public Route
app.get('/',(req,res)=>{
    res.status(200).json({msg: 'Bem vindo a nossa API'})
})
//private Route
app.get("/user/:id",checkToken,async(req,res)=>{
    const id=req.params.id
    //checar se usuario existe
   const user = await User.findById(id, '-password')
    if(!user){
        return res.status(404).json({msg: 'usuario nao encontrado'})
    }
    res.status(200).json({user})
    })

    //funcao checar token
    function checkToken(req,res,next){
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(" ")[1]
        if(!token){
            return res.status(401).json({msg: 'Acesso Negado'})
        }

        try {
            const secret = process.env.SECRET
            jwt.verify(token,secret)
            next()
        } catch (error) {
            res.status(400).json({msg:"Token Invalido"})
        }
    }
    
//Registrar Usuario
app.post('/auth/register',async(req,res)=>{
    const {name,email,password,confirmpassword} = req.body

    //validacoes
    if(!name){
        return res.status(422).json({msg: "Nome e obrigatorio!!"})
    }
    if(!email){
        return res.status(422).json({msg: "Email e obrigatorio!!"})
    }
    if(!password){
        return res.status(422).json({msg: "password e obrigatorio!!"})
    }
    
   if(password !== confirmpassword){
    return res.status(422).json({msg: "As senhas nao conferem"})
   }

   //checar se o usuario existe
   const userExist = await User.findOne({email:email})
   if(userExist){
    return res.status(422).json({msg: "Email Invalido"})
   }

   //criar senha
   const salt = await bcrypt.genSalt(12)
   const passwordHash = await bcrypt.hash(password, salt)

   //criar usuario

   const user = new User({
    name,
    email,
    password: passwordHash,
   })
   try{
    await user.save()
    res.status(201).json({msg:'Usuario criado com Sucesso'})

   }catch(error){
    console.log(error)
    
    res.status(500).json({msg:"Aconteceu um erro. Tente Novamente Mais tarde "})
   }
   

})
//Login User
app.post("/auth/login",async(req,res)=>{
    const{email, password} = req.body
    //validaco de login
    if(!email){
        return res.status(422).json({msg: "Email e obrigatorio!!"})
    }
    if(!password){
        return res.status(422).json({msg: "password e obrigatorio!!"})}

    //checar se o usuario existe
    const user = await User.findOne({email:email})
    if(!user){
     return res.status(404).json({msg: "Email nao encontrado"})
    }
    //checar senha
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg: "Password incorrect!"})
    }
    try{
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user.id,
        },secret)

        res.status(200).json({msg: "Login com sucesso",token} )
    
       }catch(error){
        console.log(error)
        
        res.status(500).json({msg:"Aconteceu um erro. Tente Novamente Mais tarde "})
       }
})

//credenciais
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

moongose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.ijoyfo2.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(() =>{
    app.listen(3000)
    console.log('Conectou Com Sucesso!!!')
}).catch((err)=> console.log(err))



