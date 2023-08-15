const express=require('express');
const mysql=require('mysql');
const cors=require('cors');
const jwt =require('jsonwebtoken')
const bcrypt=require('bcrypt')//save password correctly
const cookieParser=require('cookie-parser')//npm i cookie-parser
require('dotenv').config()


const constantSalt = '$2b$10$abcdefghijklmnopqrstuv';
const app=express();
app.use(express.json())
app.use(cors({
    origin:["http://localhost:3000"],
    methods :["POST","GET"],
    credentials :true
}));

app.use(cookieParser())

const db= mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'',
    database:'chatdb',
    port:3308
})

const verifyUser= (req,res,next)=>{
    const token= req.cookies.token;
    if(!token){
        return res.json({status:'error in token'});
    }else{
        jwt.verify(token,process.env.TOKEN_KEY,(err,decoded)=>{
            if(err){
                return res.json({status:'token incorrect'});
            }else{
                req.username=decoded.username;
                next();
            }
        })
    }
}




app.get("/",verifyUser,(req,res)=>{
    return res.json({status :'success',username :req.username});
})

app.post('/login',(req,res)=>{
    const get_querry="SELECT `username` FROM `login` WHERE `username`= ? AND `password`= ? ;";
    // const values=[
    //     req.body.username,
    //     req.body.password
    // ];
    
    // db.query(get_querry,values,(err,data)=>{
    //     if(err){
    //         return res.json({status:'error'});
    //     }else{
    //         if(data.length === 0 ){
    //             //console.log(data);
    //             return res.json({status:'error_login'});
    //         }else{
    //              return res.json({status:'success'});

    //         }
            
    //     }

    // })
    

    bcrypt.hash(req.body.password.toString(),constantSalt,(err,hash)=>{
        if(err){
            return res.json({status:'error in hashing password'});
        }else{
            const values=[
                req.body.username,
                hash
            ];
            //console.log(hash);
            db.query(get_querry,values,(err,data)=>{
                if(err){
                    return res.json({status:'error'});
                }else{
                    if(data.length === 0 ){
                        console.log(data);
                        return res.json({status:'error_login'});
                    }else{
                        const username=data[0].username;
                        //console.log(username)
                        //process.env.TOKEN_KEY
                        //env key
                        console.log("TOKEN_KEY:", process.env.TOKEN_KEY);

                        const token=jwt.sign({'username': username},process.env.TOKEN_KEY,{expiresIn:'1d'});
                        res.cookie('token',token)
                        return res.json({status:'success'});
        
                    }
                    
                }
        
            })

        }

    })

//     const saltRounds = 10; // Number of rounds for hashing

//     //const plainPassword = 'userpassword'; // This is the user's plain password

//       // Generate a random salt and hash the password
//     bcrypt.genSalt(saltRounds, (err, salt) => {
//         if (err) {
//             console.error('Error generating salt:', err);
//         } else {
//             bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
//         if (err) {
//             console.error('Error hashing password:', err);
//         } else {
//             const values=[
//                 req.body.username,
//                 hash
//             ];
//             console.log(hash);
//             db.query(get_querry,values,(err,data)=>{
//                 if(err){
//                     return res.json({status:'error'});
//                 }else{
//                     if(data.length === 0 ){
//                         //console.log(data);
//                         return res.json({status:'error_login'});
//                     }else{
//                          return res.json({status:'success'});
        
//                     }
                    
//                 }
        
//             })
//       }
//     });
//   }
// });


})


app.get("/logout",(req,res)=>{
    res.clearCookie('token')
    return res.json({status :'success'});
})

app.listen(8081,()=>{
    console.log("listening port ......")
})












