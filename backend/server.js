const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser")


const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

const saltRounds = 10;

const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "",
  database: "accredian_1",
});



app.post("/register", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const c_password = req.body.c_password;

    // Check if email format is valid
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }
  
    bcrypt.hash(password, saltRounds, (err, hash)=>{
        if(err){
            console.log(err);
        }

        db.query(
            "SELECT * FROM users WHERE email = ?",
            [email],
            (err, result) => {
              if (err) {
                return res.status(500).json({ message: "Database error" });
              }
              else if (!emailPattern.test(email)) {
                  return res.status(400).json({ message: "Invalid email format" });
                }
                else if (result.length > 0) {
                  return res.status(500).json({ message: "Email already exists" });
                } else {
                // If email doesn't exist, proceed with registration
                db.query(
                  "INSERT INTO users (email, password, c_password) VALUES (?, ?, ?)",
                  [email, hash, hash],
                  (err, result) => {
                    if (err) {
                      return res.status(500).json({ message: "Database error" });
                    }
                    res.status(200).json({ message: "Account created successfully" });
                  }
                );
              }
            }
          );

    })
    // Check if email already exists in the database
    
  });
  

  app.post("/login", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
  
    db.query(
      "SELECT * FROM users WHERE email = ?;",
      email,
      (err, result) => {
        if (err) {
          res.send({ err: err });
        }
  
        if (result.length > 0) {
          bcrypt.compare(password, result[0].password, (error, response) => {
            if (response) {
              res.send(result);
            } else {
              res.send({ message: "Wrong username/password combination!" });
            }
          });
        } else {
          res.send({ message: "User doesn't exist" });
        }
      }
    );
  });



app.listen(5000, () => {
  console.log("listening to port 5000");
});
