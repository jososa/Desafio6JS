import usersModel from "../../models/usersModel.js"

export default class userManager {
    
    getUser = async (user) => {
        try {
            return usersModel.findOne(user)
        } catch (error) {
            return error
        }
    }

    createUser = async (newUser) => {
        try {
            return await usersModel.create(newUser)
        } catch (error) {
            return error
        }
    }

    loginUser = async (userLogin) => {
        try {
            return await usersModel.findOne(userLogin)
        } catch (error) {
            return error
        }
    }

}