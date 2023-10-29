const mysql = require('mysql');
 
const pool = mysql.createPool({
    connectionLimit : 100, //important
    host     : 'localhost',
    user     : 'bilal',
    password : 'root123',
    database : 'Extension',
    waitForConnections: true,
    debug    :  false
});
module.exports=pool;