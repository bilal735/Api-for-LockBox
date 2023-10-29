const { v4: uuidv4 } = require('uuid');
//importing from modules
var obj = require("../modules/myModule");
var obj2 = require("../modules/functionality");
const pool = require("../db/connection.js");



// Json Web Token
const jwt = require("jsonwebtoken");
const config = require("../config/config")
function generateToken(req, res) {
    const key = config.secret_jwt;
    const user = {
        email: req.body.email,
        url: req.body.password
    }
    const options = {
        expiresIn: 600000 // Token will expire in 1 hour
    };

    const token = jwt.sign(user, key, options);

    console.log('JWT Token:', token);
    return token
}



// fetch all users
async function fetchAllUsers(req, res) {
    try {
        var data = await obj.fetch(req, res);
        console.log(data);
        if(data){
            console.log("data from users.js "+data)
           
            res.send(data);
        }else{
            console.log("data not found")
            res.send();
        }
        
    } catch (error) {
        console.log("error inn users.js");
        res.send();
    }
    
    
}


//Insert  OR register User 
async function registerUser(req, res) {
    console.log("Helllo");
    let result;
    try {
        result = await obj.insert(req, res);
        // console.log(result);
    } catch (error) {
        console.log("error occured in user.js");
    }
    if (result) {
        obj2.sendMail(req.body.name, req.body.email);
        res.json({
            success: 1,
            msg: "data inserted successfully"
        })
        res.status(200).send()
    } else {
        res.json({
            success: 0,
            msg: "unable to insert data!!"
        })
        res.status(200).send()
    }
    res.send();

}


//login User 
async function loginUser(req, res) {
    // res.send(req.params);
    let result = false;
    try {
        result = await obj2.check(req, res);

    } catch (error) {

        result = false;

    }
    //if(result[0].password == req.password)
    //console.log("the result is " + result);
    // console.log(typeof(req.body.password),result[0])
    if (result[0] != undefined) {
        if (result[0].password === req.body.password) {

            let object1;
            const token = generateToken(req, res);
            object1 = {
                success: 1,
                msg: "hello",
                token: token
            }
            //dfghj
            res.json(object1)
            res.send();

        } else {
            object1 = {
                success: 0,
                msg: "email or password is incorrect"                
            }
            res.json(object1)
        }
    } else {
        // console.log("else block")

        res.json({
            success: 0,
            msg: "email not found"
        })

    }

    res.send();
}


//select User by ID
// function selectUser(req, res) {
//     // res.send(req.params);
//     obj.fetchUser(req, res);

// }


//delete the user by id
async function deleteUser(req, res) {
    try {
        await obj.deleteUser(req, res);
        res.json({
            success :1
        })
        res.send();
    } catch (error) {
        res.json({
            success :0
        })
        res.send();
    }
   
}


//updating users
function updateUser(req, res) {
    const { id } = req.params;
    const { name, email, password } = req.body;

    if (name) {
        let s = "UPDATE user_table SET name = '" + name + "' WHERE id='" + id + "' ;"
        obj.updateUser(s, req, res);
    } else
        if (email) {
            let s = "UPDATE user_table SET email = '" + email + "' WHERE id='" + id + "' ;"
            obj.updateUser(s, req, res);
        } else
            if (password) {
                let s = "UPDATE user_table SET password = '" + password + "' WHERE id='" + id + "' ;"
                obj.updateUser(s, req, res);
            } else {
                res.json({
                    success: 0
                })
                res.send();
            }

}

//Create and Store  Ciphered Password 
async function createCipherAndStore(req, res) {
    const email = req.body.email;
   // const length = 10//req.body.length;
    const url = req.body.url;
    const objPass = req.body.objPass;
    const object2 = obj2.objCipherHash(objPass);
    const hash = object2.hash;
    const cipher = object2.cipher;
    const user_name= req.body.user_name ;
    try {
        const result = await obj.storeCipher(email, cipher, url,user_name);
        res.json({
            success: 1,
            msg: "password is successfully Created and sent",
            password: hash

        })
    } catch (error) {
        res.json({
            success: 0
        })
    }

    res.send();
}

//fetching ciphered password and converting into hash and returnnig it as Json
async function returnCipheredPassword(req, res) {
    try {
        const result = await obj.fetchCipher(req.body.email, req.body.url);
        if (result != undefined) {
            console.log(result[0].password + " this is cipher")
            const password = obj2.decryptCipher(result[0].password);
            res.json({
                success: 1,
                msg: "the fetched password sent!!!",
                password: password,
                user_name : result[0].user_name
            })
        } else {
            res.json({
                success: 0,
                msg: ""

            })
        }

    } catch (error) {
        res.json({
            success: 0
        })
    }
    res.send();
}

module.exports = {
    fetchUsers: fetchAllUsers,
    registerUser: registerUser,
    // selectUser: selectUser,
    deleteUser: deleteUser,
    updateUser: updateUser,
    createCipherAndStore: createCipherAndStore,
    returnCipheredPassword: returnCipheredPassword,
    loginUser: loginUser,
    generateToken: generateToken
}