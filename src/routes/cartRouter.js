import { Router } from "express"
import fs from "fs"
//import { CartManager } from '../dao/controllers/fileSystem/CartManager.js'
import CartManager from "../dao/controllers/mongoDB/cartManagerMongo.js"
import ProductManager from "../dao/controllers/mongoDB/productManagerMongo.js"

const carrito = new CartManager()
const productos = new ProductManager()

const cartRouter = Router()

//Alta de carrito
cartRouter.post("/", async (req, res) => {
    try {
        const newCart = await carrito.createCart();
        res.status(201).send({ status: "Carrito creado", payload: newCart })
    } catch (error) {
        console.log(error)
        res.status(500).send({ status: "Error al crear el carrito",  error: error.message })
    }
})

//Obtener carritos
cartRouter.get("/",async(req,res)=>{
    const cart = await carrito.getCarts()
    res.json({cart})
 })

//Obtener carrito por ID
cartRouter.get("/:cid", async (req, res) => {

    try {
        const cid = req.params.cid;
        const cart = await carrito.getCartById(cid)
        res.json(cart)
    } catch (error) {
        console.log(error)
        res.status(500).send({ status: "Internal Server Error",  error: error.message})
    }
})

//Agregar producto al carrito
cartRouter.post("/:cid/product/:pid", async (req, res) => {
    const { cid, pid } = req.params
    const { quantity } = req.body

    try {
      const updatedCart = await carrito.addProductsToCart(cid, pid, quantity)
      res.status(201).send({ status: "success", payload: updatedCart })
    } catch (error) {
        res.status(500).send({ status: "error",  error: error.message })
    }
})

//Modificar carrito
cartRouter.put('/:cid', async (req, res) => {
    try {
        const cid = req.params.cid
        const {products} = req.body
    
        const result = await carrito.updateProductsInCart(cid, products)
    
        res.status(200).send({ status: "Carrito actualizado con exito" })
    } catch (error) {
        console.log(error)
    }
  })

//Actualiza la cantidad de un producto específico en el carrito
cartRouter.put('/:cid/products/:pid', async (req, res) => {
      const { cid, pid } = req.params
      const { quantity } = req.body
      try {
          const updatedCart = await carrito.updateProductQuantity(cid, pid, quantity)
          res.status(200).send({ status: "success", payload: updatedCart })
      } catch (error) {
          console.log(error)
          res.status(500).send({ status: "error",  error: error.message })
      }
  })

//Eliminar producto del carrito
cartRouter.delete('/:cid/products/:pid', async (req, res) => {
    const { cid, pid } = req.params
    try {
        await carrito.removeProductFromCart(cid, pid)
        res.status(200).send({ status: "success", message: `Se elimino producto ID: ${pid} del carrito` })
    } catch (error) {
        console.log(error)
        res.status(500).send({ status: "error",  error: error.message })
    }
})

//Eliminar carrito
cartRouter.delete('/:cid', async (req, res) => {
  const { cid } = req.params;
  try {
      await carrito.clearCart(cid);
      res.status(204).send({ status: "success", message: `Carrito ID: ${cid} eliminado con exito`, payload: null });
  } catch (error) {
      console.log(error);
      res.status(500).send({ status: "error",  error: error.message });
  }
  })

export default cartRouter