import mongoose, {Schema} from "mongoose"

const collectionUsers = "Users"

const schemaUsers = new Schema({
    first_name: {
        type: String,
        require: true
    },
    last_name: {
        type: String,
        require: true
    },
    email: {
        type: String,
        require: true
    },
    age: {
        type: Number,
        require: true
    },
    password: {
        type: String,
        require: true
    },
    role: { 
        type: String,
        require: true 
    },
})

const usersModel = mongoose.model(collectionUsers, schemaUsers)

export default usersModel