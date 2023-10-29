const jwt = require("jsonwebtoken")
const config = require("../config/config");

const verifyToken = async (req, res, next) => {

    const secretKey=config.secret_jwt;
    const token = req.body.token || req.query.token || req.headers["token"];
    if (token) {
        
            jwt.verify(token, secretKey, (error, decodedToken) => {
                if (error) {
                    console.error('JWT verification failed:', error.message);
                    res.status(400).send({success:0,msg:"Invalid Token"});
                } else {
                    console.log('Decoded JWT Token:', decodedToken);
                    req.body.email=decodedToken.email;
                    //req.body.url=decodedToken.url;

                    next();
                }
            });
     
    }else{
        res.status(400).send({success:0,msg:"token require"});
    }
}
module.exports = verifyToken;