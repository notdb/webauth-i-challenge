const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

// require bcrypt
const bcrypt = require("bcryptjs");

const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

const sessionConfig = {
  name: "monkey1",
  secret: "keep it secret, keep it safe!",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 10,
    secure: false,
    httpOnly: true
  },
  store: new KnexSessionStore({
    knex: require("./database/dbConfig.js"),
    tablename: "sessions",
    sidfieldname: "sid",
    createtable: true,
    createInterval: (1000 * 60) & 30
  })
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  // hash the password
  const hash = bcrypt.hashSync(user.password, 8); // password gets re-hashed 2^8 times
  // re-assign user password
  user.password = hash;
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.username = user.username;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json({ users, username: req.session.username });
    })
    .catch(err => res.send(err));
});

function restricted(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: "Invalid Credentials" });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    res.status(400).json({ message: "please enter a username and password" });
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
