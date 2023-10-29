const express=require("express");
const bodyParser=require("body-parser");

const usersRoutes=require('./routes/allRoutes.js');

const app=express();
const Port =5434;


//cors implementation
const cors=require("cors");
const corsOption={
    origin : "http://127.0.0.1:5500/",
    optionsSuccessStatus : 200
};
app.use(cors());



  
app.use(bodyParser.json());

app.use('/api',usersRoutes);

app.listen(Port,()=>{
    console.log(`server is runnig at http://localhost:${Port}`);
});
