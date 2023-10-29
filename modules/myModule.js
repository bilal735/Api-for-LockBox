var pool = require("../db/connection");
var obj2 = require("./functionality");
// const mysql = require('./mysql2/promise');
//Selecting all users
async function fetch(req, res) {
    const email = req.body.email || req.query.email || req.headers["email"];
    if (email) {
        const q = "select * from cipher_password where email='" + email + "'";
        const p = new Promise((resolve, reject) => {
            pool.query(q, (error, data) => {
                if (error) {
                    console.log(error);
                    return reject(false);
                } else {
                    console.log("data is here " + data)
                    return resolve(data);
                }

            })
        })
        try {
            const d = await p;
            for (let index = 0; index < d.length; index++) {
                const element = d[index].password;
               // console.log(element);
                d[index].password=element;
                d[index].password2=obj2.decryptCipher(element);
               // console.log(d[index].password);
            }
            return d;
        } catch (error) {
            const d = false;
            return d;
        }
    } else {

        console.log("else part from fetch");
        return false;
    }

}

//Inserting User Details
async function insert(req, res) {

    let name = req.body.name;
    let email = req.body.email;
    let password = req.body.password;
    //printing data
    //console.log(name,email,password);
    var q = "insert into user_table(name,email,password,status) value(?,?,?,?)";
    let values = [
        name,
        email,
        password,
        0
    ]
    try {
        // Execute a query using pool.query()
        await pool.query(q, values);
        console.log("data inserted");
        return true;

    } catch (error) {

        console.error('Error executing query:', error);
        return false;
    }
    return false;

}

//selecting user by id
// function fetchUser(req, res) {
//     const q = "select * from user_table where id='" + req.params.id + "'";
//     pool.query(q, (error, data) => {
//         if (error) {
//             console.log(error);
//             res.json({
//                 success: 0
//             });
//             res.send();
//         } else {
//             res.json(data);
//             res.send();
//         }

//     })
// }

//delete user by id
function deleteUser(req, res) {
    const email = req.body.email || req.query.email || req.headers["email"];
    const pwd = req.body.password || req.query.password || req.headers["password"];
    console.log(pwd);
   //const pwd1=obj2.encryptCipher(""+pwd);
    //console.log(obj2.encryptCipher(pwd));
    const q = "delete from cipher_password where email='" + email + "' and password='" + pwd + "';"
    console.log(email, pwd)
    if (email && pwd){
        return new Promise((resolve, reject) => {
            pool.query(q, (error, data) => {
                if (error) {
                    console.log(error);
                    return resolve(error);
                } else {
                    console.log("data " + data);
                    return resolve(data);
                }
            });
        })

    }

}

//updating the user
function updateUser(q, req, res) {
    return new Promise((resolve, reject) => {
        pool.query(q, (error, data) => {
            if (error) {
                return reject(error);
            }
            return resolve(data);
        });
    })

}


//Storing the Cipher
async function storeCipher(email, cipher, url,user_name) {
    let domain;
    // Find & remove protocol (http, ftp, etc.) and get domain
    if (url.indexOf('://') > -1) {
        domain = url.split('/')[2];
    } else {
        domain = url.split('/')[0];
    }
    domain = domain.split(':')[0];
    url = domain;
    const un= user_name || 'undefined' ;
    const q = "INSERT INTO cipher_password VALUES('" + email + "','" + cipher + "','" + url + "','"+un+"');"
    return new Promise((resolve, reject) => {
        pool.query(q, (error, result) => {
            if (error) {
                return reject(error);
            }
            return resolve(result);
        });

    })
}


// fetching the cipher from the table
async function fetchCipher(email, url) {
    const q = "select * from cipher_password where(email='" + email + "' and url='" + url + "');"
    return new Promise((resolve, reject) => {
        pool.query(q, (error, result) => {
            if (error) {
                return reject(error);
            }
            return resolve(result);
        });

    })
}




module.exports = {
    // fetch: fetch,
    insert: insert,
    fetch: fetch,
    deleteUser: deleteUser,
    updateUser: updateUser,
    storeCipher: storeCipher,
    fetchCipher: fetchCipher
}