import passport from "passport"
import local from "passport-local"
import GitHubStrategy from "passport-github2"
import usersModel from "../dao/models/usersModel.js"
import {createHash, isValidPassword} from "../utils.js"

const LocalStrategy = local.Strategy

const initializePassport = () => {
    //Estrategia registro de usuario
    passport.use('register', new LocalStrategy({passReqToCallback:true, usernameField:"email"},
    async(req, username, password, done) =>{
        const {first_name, last_name, email, age} = req.body
        try {
            const user = await usersModel.findOne({email:username})
            if(user){
                console.log("El usuario ya existe")
                return done(null, false)
            }
            const newUser={
                first_name,
                last_name,
                email,
                age,
                password:createHash(password),
            }

            const result = await usersModel.create(newUser)
                return done(null,result)
        } catch (error) {
            return done(error)
        }
    })
)

//Estrategia de login
passport.use("login", new LocalStrategy({usernameField:"email"}, async(username, password, done)=>{
    try {
        const user = await usersModel.findOne({email:username})
        if(!user){
            return done(null, false)
        }
        const valid = isValidPassword(user, password)
        if(!valid){
            return done(null,user)
        }
    } catch (error) {
        return done(error)
    }
}))

//Login con Github
passport.use("github", new GitHubStrategy({
    clientID:"Iv1.17076b57af2af99d",
    clientSecret:"aefeb76ab4e023adbb0544d033557a15fe841997",
    callbackURL:"http://localhost:8080/api/sessions/githubcallback",
},
    async(accessToken, refreshToken, profile, done) => {
        try {
            console.log(profile)
            const user = await usersModel.findOne({email: profile._json.email,})

            if(!user){
                const newUser = {
                    first_name: profile._json.name,
                    last_name: "",
                    age: 20,
                    email: profile._json.name,
                    password: "",
                }
                let createdUser = await usersModel.create(newUser)
                done(null,createdUser)
            }
            else{
                done(null, user)
            }
        } catch (error) {
            return done(error)
        }
    })  
)

passport.serializeUser((user, done)=>{
    done(null,user._id)
})

passport.deserializeUser(async(id, done)=>{
    try {
        const user = await usersModel.findById(id)
    } catch (error) {
        done(error)
    }
})

}

export default initializePassport