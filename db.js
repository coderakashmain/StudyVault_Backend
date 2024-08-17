require('dotenv').config();
const mysql = require("mysql2") 

const connectionUserdb = mysql.createConnection({
    host : process.env.DB_HOST,
    user : process.env.DB_USER,
    password : process.env.DB_PASSWORD,
    database : 'userdb'
})
const connectionPaperdb = mysql.createConnection({
    host : process.env.DB_HOST,
    user : process.env.DB_USER,
    password : process.env.DB_PASSWORD,
    database : 'papersdb'
})

connectionUserdb.connect((err)=>{
    if(err){
        console.error('Error connecting to the database:',err);
        return;
    }
    else{
        console.log('Connected to the user database.');
    }
});
connectionPaperdb.connect((err)=>{
    if(err){
        console.error('Error connecting to the database:',err);
        return;
    }
    else{
        console.log('Connected to the papers database.');
    }
});

module.exports = {
    connectionUserdb,
    connectionPaperdb
};