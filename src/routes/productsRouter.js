import { Router } from "express"
import fs from "fs"
//import { ProductManager } from '../dao/controllers/fileSystem/ProductManager.js'
import ProductManager from '../dao/controllers/mongoDB/productManagerMongo.js'

const productos = new ProductManager()

const productsRouter = Router()

//Obtener productos
productsRouter.get("/", async (req, res) => {
  try {
    const products = await productos.getAllProducts(req.query);
    res.status(200).send({ status: "success", payload: products });
  } catch (error) {
    console.log(error);
    res.status(500).send({ status: "error", error: error.message });
  }
})

//Obtener producto por ID
productsRouter.get("/:pid", async (req, res) => {
  const { pid } = req.params
  try {
    const product = await productos.getProductById(pid)
    if (!product) {
      return res
        .status(404)
        .send({ status: "error", error: "Product not found" })
    }
    res.status(200).send({ status: "success", payload: product })
  } catch (error) {
    console.log(error)
    res.status(500).send({ status: "error", error: error.message })
  }
})

//Crear producto
productsRouter.post("/", async (req, res) => {
    const newProduct = req.body;
    try {
      let result = await productos.addProduct(newProduct)
      res.json({result})//({message: "Producto agregado"})
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
})

//Modificar producto
productsRouter.put("/:prodId", async (req, res) => {

    const productId = req.params.prodId
    const updatedFields = req.body
    try {
      const updatedProduct = await productos.updateProduct(
        productId,
        updatedFields
      );
      res.json({ status: "Producto actualizado", updatedProduct })
    } catch (error) {
      res.status(400).json({ error: error.message })
    }
})

//Eliminar producto
productsRouter.delete("/:prodId", async (req, res) => {

    const productId = req.params.prodId
    try {
      await productos.deleteProduct(productId)
      res.json({ status: "Producto eliminado" })
    } catch (error) {
      res.status(400).json({ error: error.message })
    }
})

export default productsRouter