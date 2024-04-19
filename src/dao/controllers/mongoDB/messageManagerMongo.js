import messageModel from '../../models/messagesModel.js'

export default class MessageManager{

    getMessages = async () => {
        try {
            return await messageModel.find()
        } catch (error) {
            return error
        }
    }

    createMessage = async (msg) => {
        if(msg.user.trim() === '' || msg.message.trim() === ''){
            return null
        }
        try {
            return await messageModel.create(msg)
        } catch (error) {
            return error
        }
    }

}