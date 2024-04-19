import cartsModel from "../../models/cartsModel.js"
import productsModel from "../../models/productsModel.js"
import { isValidObjectId } from "../../../utils.js"

export default class CartManager {

     getOrCreateCart = async () => {
        let cart = await cartsModel.findOne().lean()
        if (!cart) {
          cart = await this.createCart()
        }
        return cart
      }

    getCarts = async () => {
        try {
            const carts = await cartsModel.find().lean();
            return carts
        } catch (err) {
            console.error('Error al obtener los carritos:', err.message)
            return []
        }
    };
    

    getCartById = async (cartId) => {
        try {
            const cartById = await cartsModel.findById(cartId).populate("products.product").lean()
            return(cartById)
        } catch (err) {
            return err.message
        }
    }

    createCart = async (products) => {
        try {
            let cartData = {};
            if (products && products.length > 0) {
                cartData.products = products
            }
    
            const cart = await cartsModel.create(cartData)
            return cart
        } catch (err) {
            console.error('Error al crear el carrito:', err.message)
            return err
        }
    }
  

    async addProductsToCart(cartId, productId, quantity) {
        const cart = await cartsModel.findById(cartId)
        const product = cart.products.find(
          (product) => product.product.toString() === productId.toString()
        )
        if (product) {
          product.quantity += quantity
        } else {
          cart.products.push({ product: productId ,quantity })
        }
        return await cart.save()
      }

      
    updateProductsInCart = async (cid, products) => {
        try {
            return await cartsModel.findOneAndUpdate(
                { _id: cid },
                { products },
                { new: true })

        } catch (err) {
            return err
        }
    }


    async updateProductQuantity(cartId, productId, quantity) {
        try {
            const cart = await cartsModel.findById(cartId)
            const product = cart.products.find(
              (product) => product.product.toString() === productId.toString()
            )
            if (product) {
              product.quantity = quantity
            } else {
              cart.products.push({ product: productId ,quantity })
            }
              return await cart.save()
        }
        catch (error) {
            console.error("No se pudo actualizar la cantidad del producto", error)
        }
    }


    updateOneProduct = async (cid, products) => {
        
        await cartsModel.updateOne(
            { _id: cid },
            {products})
        return await cartsModel.findOne({ _id: cid })
    }


    removeProductFromCart = async (cid, pid) => {
        const cart = await cartsModel.findById(cid)
        cart.products = cart.products.filter((product) => product._id.toString() !== pid)
        return cart.save()
      }


    clearCart = async (cid) => {
    const cart = await cartsModel.findById(cid)
        if (!cart) {
          throw new Error("El carrito no existe")
        }
        cart.products = []
        return cart.save()
    }

}