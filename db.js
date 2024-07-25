const mysql = require("mysql2") 

const connectionUserdb = mysql.createConnection({
    host : 'localhost',
    user : 'root',
    password : '814495@mySQL',
    database : 'userdb'
})
const connectionPaperdb = mysql.createConnection({
    host : 'localhost',
    user : 'root',
    password : '814495@mySQL',
    database : 'PapersDB'
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