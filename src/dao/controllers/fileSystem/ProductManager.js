import {promises as fs} from 'fs'

export class ProductManager {
    constructor() {
        this.path = 'src/dao/data/Products.json'
        this.products = []
        this.lastProductId = 0
    }


    validate(title, description, code, price, stock, category) {
        if (!title || !description || !code || !price || !stock || !category) {
            throw new Error("Todos los campos son obligatorios.")
        }

        if (this.products.some(product => product.code === code)) {
            throw new Error("El código del producto ya está en uso.")
        }
    }


    addProduct = async (newProduct) => {

        try {
            this.validate(newProduct.title, newProduct.description, newProduct.code, newProduct.price, newProduct.stock, newProduct.category)

            let productsOld = await this.getProducts()

            newProduct.id = productsOld.length + 1

           let productAll = [...productsOld, newProduct]

            return fs.writeFile(this.path, JSON.stringify(productAll))

        } catch (error) {
            console.error(error.message)
        }
    }


    getProducts = async () => {
        let response = await fs.readFile(this.path, "utf-8")
        let result=JSON.parse(response)
        return result
    }


    getProductById = async (productId) => {
        let result = await this.getProducts()
        let prod = result.find(product => product.id === productId)

        if (prod) {
            return prod;
        } else {
            console.error(`Producto no encontrado. ID: ${productId}`)
            return null;
        }
    }

    deleteProduct = async (productId) => {

        try {
            let products = await this.getProducts()
            const index = products.findIndex((product) => product.id == productId)

            if (index === -1) {
                console.error(`No se encontró ningún producto con el ID ${productId}`)
                throw new Error(`No se encontró ningún producto con el ID ${productId}`)
            }

            products.splice(index, 1);
            await fs.writeFile(this.path, JSON.stringify(products))

            return 1
            
        } catch (error) {
            console.log(`Error al borrar el producto con ID ${productId}: ${error}`)
            throw new Error("Error al borrar el producto");
        }
        
    }

    updateProduct = async (pid, campo) => {
        console.log(pid)
        console.log(campo)
        try {
            let products = await this.getProducts();
            const index = products.findIndex((product) => product.id == pid)

            if (index === -1) {
                console.error(`No se encontró ningún producto con el ID ${pid}`)
                throw new Error(`No se encontró ningún producto con el ID ${pid}`)
            }

            const id=pid;
            products[index] = { ...products[index], ...campo, id }
            await fs.writeFile(this.path, JSON.stringify(products))
            return products[index]
            
        } catch (error) {
            console.log(error)
            throw new Error("Error al actualizar el producto")
        }

    }

}

export default ProductManager
