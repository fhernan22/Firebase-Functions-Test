const functions = require("firebase-functions");
const firebase = require("firebase");
const admin = require("firebase-admin");
const express = require("express");

const config = require("./util/config");

admin.initializeApp();
firebase.initializeApp(config);
const db = admin.firestore();
const app = express();
const cors = require("cors")({ origin: true });

const { validateSignUpData, validateLoginData } = require("./util/validators");

// Authentication Middleware
const FBAuth = (req, res, next) => {
  let idToken;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    idToken = req.headers.authorization.split("Bearer ")[1];
  } else {
    console.error("No token found");
    return res.status(403).json({ error: "Unauthorized" });
  }

  admin
    .auth()
    .verifyIdToken(idToken)
    .then((decodedToken) => {
      req.user = decodedToken;

      return db
        .collection("users")
        .where("userId", "==", req.user.uid)
        .limit(1)
        .get();
    })
    .then((data) => {
      req.user.username = data.docs[0].data().username;
      return next();
    })
    .catch((err) => {
      console.error("Error while verifying token ", err);
      return res.status(403).json(err);
    });
};

////////////////////////////////////////////////////////
// Authentication routes
////////////////////////////////////////////////////////

app.use(cors);

app.post("/signup", (req, res) => {
  const newUser = {
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    username: req.body.username,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  };

  const { valid, errors } = validateSignUpData(newUser);

  if (!valid) return res.status(400).json(errors);

  let token, userId;

  db.doc(`/users/${newUser.username}`)
    .get()
    .then((doc) => {
      if (doc.exists) {
        return res
          .status(400)
          .json({ username: "This username is already taken" });
      } else {
        return firebase
          .auth()
          .createUserWithEmailAndPassword(newUser.email, newUser.password);
      }
    })
    .then((data) => {
      userId = data.user.uid;
      return data.user.getIdToken();
    })
    .then((idToken) => {
      token = idToken;

      console.log(newUser);

      const userCredentials = {
        username: newUser.username,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        createdAt: new Date().toISOString(),
        userId,
      };
      console.log(userCredentials);
      return db.doc(`/users/${newUser.username}`).set(userCredentials);
    })
    .then(() => {
      return res.status(201).json({ token });
    })
    .catch((err) => {
      console.error(err);

      if (err.code === "auth/email-already-in-use") {
        return res.status(400).json({ email: "Email already in use" });
      } else {
        console.error(err);
        return res
          .status(500)
          .json({ general: "Something went wrong. Please try again" });
      }
    });
});

app.post("/login", (req, res) => {
  const user = {
    email: req.body.email,
    password: req.body.password,
  };

  const { valid, errors } = validateLoginData(user);

  if (!valid) return res.status(400).json(errors);

  firebase
    .auth()
    .signInWithEmailAndPassword(user.email, user.password)
    .then((data) => {
      return data.user.getIdToken();
    })
    .then((token) => {
      return res.json({ token });
    })
    .catch((err) => {
      console.error(err);

      return res
        .status(403)
        .json({ general: "Wrong credentials. Please try again" });
    });
});

// Test
app.get("/user/:username", FBAuth, (req, res) => {
  let userData = {};
  db.doc(`/users/${req.params.username}`)
    .get()
    .then((doc) => {
      if (doc.exists) {
        userData.user = doc.data();
      } else {
        return res.status(404).json({ errror: "User not found" });
      }

      return res.status(200).json(userData);
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ error: err.code });
    });
});

exports.api = functions.https.onRequest(app);
