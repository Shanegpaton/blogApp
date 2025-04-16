require("dotenv").config()
const sanititzeHTML = require("sanitize-html")
const marked = require("marked")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")
const express = require("express")
const app = express()
const db = require("better-sqlite3")("ourApp.db")

//db setup
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        )
        `
    ).run()
})

createTables()

db.pragma("journal_mode = WAL")
app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {
    // make our markdown function available
    res.locals.filterUserHTML = function (content) {
        return sanititzeHTML(marked.parse(content), {
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
            allowedAttributes: {}
        })
    }
    res.locals.errors = []
    //try to decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch (err) {
        req.user = false
    }

    res.locals.user = req.user
    next()
})

app.get("/", (req, res) => {
    if (req.user) {
        const postStatment = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC")
        const posts = postStatment.all(req.user.userid)
        return res.render("dashboard", { posts })
    }
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.post("/login", (req, res) => {
    let errors = []

    if (typeof req.body.username != "string") req.body.username = ""
    if (typeof req.body.password != "string") req.body.password = ""

    if (req.body.username.trim() == "") errors = ["Invalid username/ password"]
    if (req.body.password.trim() == "") errors = ["Invalid username/ password"]
    if (errors.length) {
        return res.render("login", { errors })
    }
    const userInQuestionStatment = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatment.get(req.body.username)

    if (!userInQuestion) {
        errors = ["Invalid username/ password"]
        return res.render("login", { errors })
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot) {
        errors = ["Invalid username/ password"]
        return res.render("login", { errors })
    }

    // give cookie and redirect
    const ourTokenValue = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: userInQuestion.id, username: userInQuestion.username }, process.env.JWTSECRET)
    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")


})

function mustBeLoggedIn(req, res, next) {
    if (req.user) {
        return next()
    }
    return res.redirect("/")
}

function sharedPostValidation(req) {
    const errors = []

    if (typeof req.body.title !== "string") req.body.title = ""
    if (typeof req.body.body !== "string") req.body.body = ""

    req.body.title = sanititzeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} })
    req.body.body = sanititzeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} })

    if (!req.body.title) errors.push("You must provide a title.")
    if (!req.body.body) errors.push("You must provide content.")

    return errors
}

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    // try too look up the post in question
    const statment = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statment.get(req.params.id)

    if (!post) {
        return res.redirect("/")
    }
    // if you are not the author redirect to home page
    if (post.authorid !== req.user.userid) {
        return res.redirect("/")
    }
    // otherwise render the edit post template
    res.render("edit-post", { post })
})

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    // try too look up the post in question
    const statment = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statment.get(req.params.id)

    if (!post) {
        return res.redirect("/")
    }
    // if you are not the author redirect to home page
    if (post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    const errors = sharedPostValidation(req)

    if (errors.length) {
        return res.render("edit-post", { errors })
    }
    const updateStatment = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
    updateStatment.run(req.body.title, req.body.body, req.params.id)

    res.redirect(`/post/${req.params.id}`)
})

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
    // try too look up the post in question
    const statment = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statment.get(req.params.id)

    if (!post) {
        return res.redirect("/")
    }
    // if you are not the author redirect to home page
    if (post.authorid !== req.user.userid) {
        return res.redirect("/")
    }

    const deleteStatment = db.prepare("DELETE FROM posts WHERE id = ?")
    deleteStatment.run(req.params.id)

    res.redirect("/")
})

app.get("/post/:id", (req, res) => {
    const statment = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statment.get(req.params.id)

    if (!post) {
        return res.redirect("/")
    }
    const isAuthor = post.authorid === req.user.userid
    res.render("single-post", { post, isAuthor })
})

app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post")
})

app.post("/create-post", (req, res) => {
    const errors = sharedPostValidation(req)

    if (errors.length) {
        return res.render("create-post", { errors })
    }

    // save into database
    const ourStatment = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
    const result = ourStatment.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

    const getPostStatment = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const realPost = getPostStatment.get(result.lastInsertRowid)

    res.redirect(`/post/${realPost.id}`)
})
app.post("/register", mustBeLoggedIn, (req, res) => {
    const errors = []

    if (typeof req.body.username != "string") req.body.username = ""
    if (typeof req.body.password != "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    if (!req.body.username) errors.push("You must provide a username")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be atleast 3 characters")
    if (req.body.username && req.body.username.length > 10) errors.push("Username cannot exeed 10 characters")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain regular numbers and letters")

    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)
    if (usernameCheck) errors.push("That username is already taken")

    if (!req.body.password) errors.push("You must provide a password")
    if (req.body.password && req.body.password.length < 4) errors.push("Password must be atleast 4 characters")
    if (req.body.password && req.body.password.length > 25) errors.push("Password cannot exeed 25 characters")

    if (errors.length) {
        return res.render("homepage", { errors })
    }

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)
    const ourStatment = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatment.run(req.body.username, req.body.password)
    const lookupStatment = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatment.get(result.lastInsertRowid)
    // log the user in by giving them a cookie
    const ourTokenValue = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username }, process.env.JWTSECRET)
    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")


})
app.listen(8080)