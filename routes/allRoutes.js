const express=require("express");
const router=express.Router();
const obj=require("../controllers/users")

const auth=require("../middleware/auth")


// router.post('/token',obj.generateToken);


//fetch all users
router.get('/allPassword',auth,obj.fetchUsers);

// Inserting the user id
router.post('/',obj.registerUser);


//login route...
router.post('/login',obj.loginUser);


//storinig ciphered password
router.post('/setPassword',auth,obj.createCipherAndStore);

//fetching ciphered >> hash password
router.post('/getPassword',auth,obj.returnCipheredPassword);


//deleting the users
router.delete("/delete",auth,obj.deleteUser)


//updating particular user using id
// router.patch("/:id",obj.updateUser)



module.exports=router;