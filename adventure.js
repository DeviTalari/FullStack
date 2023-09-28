const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const serviceAccount = require("./key.json");

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

app.get('/signin', (req, res) => {
    res.sendFile(__dirname + "/public/signup.html");
});

app.post('/signin', async (req, res) => {
    try {
        const email = req.body.Email;
        const password = req.body.Password;
        const confirmPassword = req.body.ConfirmPassword;
        // Check if the password and confirm password match
        if (password !== confirmPassword) {
            return res.status(400).send('Password and confirm password do not match.');
        }
        const hashedPassword = await bcrypt.hash(req.body.Password, 10);
         // Check if the email already exists
        const emailSnapshot = await db.collection('userDemo').where('Email', '==', email).get();
        if (!emailSnapshot.empty) {
            return res.status(400).send('Email already exists. Please use a different email.');
        }

        const userData = {
            Fullname: req.body.Fullname,
            Email: req.body.Email,
            Password: hashedPassword  // Save the hashed password to the database
        };

        const docRef = await db.collection('userDemo').add(userData);
        console.log('Document written with ID: ', docRef.id);

        res.send("Signup successful, please login.");
    } catch (error) {
        console.error("Error adding document: ", error);
        res.status(500).send("Signup failed.");
    }
});

app.get('/login', async(req, res) => {
    res.sendFile(__dirname + "/public/login.html");
});
  

app.post('/login', async (req, res) => {
    const email = req.body.Email;
    const password = req.body.Password;

    try {
        const querySnapshot = await db.collection('userDemo')
            .where("Email", "==", email)
            .get();

        if (querySnapshot.empty) {
            res.send("Login failed: User not found");
            return;
        }

        const userData = querySnapshot.docs[0].data();
        const hashedPassword = userData.Password;

        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (passwordMatch) {
            // Redirect to adventure page after successful login
            res.redirect("/adventure");
        } else {
            res.send("Login failed: Incorrect password");
        }
    } catch (error) {
        console.error("Error querying document: ", error);
        res.status(500).send("Login failed.");
    }
});


app.get('/adventure', (req, res) => {
    res.sendFile(__dirname + "/public/adventure.html");
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
