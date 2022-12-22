var express = require('express')
var cors = require('cors')
var app = express()
//เก็บข้อมุลจากเส้นregister
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()

//เข้ารหัส
const bcrypt = require('bcrypt');
//gen password
const saltRounds = 10;

var jwt = require('jsonwebtoken');
const secret = 'BackEndRT'

app.use(cors())

//ส่งข้อมูลเข้าsql
const mysql = require('mysql2');

// create the connection to database
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'sedb'
});

//ส่งข้อมูลเข้าdata base ผ่านเส้นregister
app.post('/register', jsonParser, function (req, res, next) {
    //hash
    bcrypt.hash(req.body.Password, saltRounds, function(err, hash) {
        connection.execute(
            'INSERT INTO user (Fname, Lname, UserName, Password, IDCard, Email, PhoneNumber) VALUES(?, ?, ?, ?, ?, ?, ?)',
            [req.body.Fname, req.body.Lname, req.body.UserName, hash, req.body.IDCard, req.body.Email, req.body.PhoneNumber],
            function(err, results, fields) {
                if (err) {
                    res.json({status: 'error', message: err})
                    return
                }
                res.json({status : 'ok'})
            }
        );
    });
})

app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM user WHERE UserName = ?',
        [req.body.UserName],
        function(err, user, fields) {
            if (err) { res.json({status: 'error', message: err}); return }
            if (user.length == 0) { res.json({status: 'error', message: err}); return }

            //ตรวจpasswordที่่hashกับในdata baseตรงกันมั้ย
            bcrypt.compare(req.body.Password, user[0].Password, function(err, isLogin) {
                if(isLogin){
                    var token = jwt.sign({ UserName: user[0].UserName}, secret, { expiresIn: '1h' } );
                    res.json({status: 'ok', message: 'login success', token})
                } else {
                    res.json({status: 'error', message: 'login failed'})
                }
            });
        }
    );
})

app.post('/authen', jsonParser, function (req, res, next) {

    try{
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({status: 'ok', decoded})
    } catch(err){
        res.json({status: 'error', message: err.message})
    }
})

app.listen(3333, function () {
  console.log('CORS-enabled web server listening on port 3333')
})