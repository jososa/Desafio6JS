import mongoose from "mongoose"

const connectionString = "mongodb+srv://user2024:NewP4ss.2024@ecommerce.fyo85ww.mongodb.net/?retryWrites=true&w=majority&appName=ecommerce"

const connectMongoDB = () => {
    try {
        mongoose.connect(connectionString)
        console.log('Conectado a mongoDB')
    } catch (error) {
        console.log(error)
    }
}

export default connectMongoDB