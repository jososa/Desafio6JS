import productsModel from "../../models/productsModel.js"

export default class ProductManager {

    async getAllProducts(params) {
        const {
          limit = 10, // default limit = 10
          page = 1, // default page = 1
          sort = null,
          query = null,
          category = null,
          status = null, //available
        } = params
    
        const options = {
          query: query,
          page: Number(page),
          limit: Number(limit),
          lean: true,
          sort: sort ? { price: sort === "asc" ? 1 : -1 } : {},
          customLabels: {
            docs: "products",
            totalDocs: "totalProducts",
          },
        }
    
        let searchQuery = {};
    
        // $options: 'i' en MongoDB se utiliza para hacer que la búsqueda sea insensible a mayúsculas y minúsculas.
        if (query) {
          searchQuery.title = { $regex: query, $options: "i" }
        }
    
        if (category) {
          searchQuery.category = { $regex: category, $options: "i" }
        }
    
        if (status !== null) {
          searchQuery.status = status === "true"
        }
    
        const result = await productsModel.paginate(searchQuery, options)
        return result
      }

    addProduct = async (newProduct) => {
        try {
            return await productsModel.create(newProduct)
        } catch (error) {
            return error
        }
    }

    getProducts = async () => {
        try {
            let result = await productsModel.find().lean()
            return result
        } catch (error) {
            return error
        }
    }

    getProductById = async (productId) => {
        try {
            return await productsModel.findById(productId)
        } catch (error) {
            return error
        }
    }

    deleteProduct = async (productId) => {
        try {
            return await productsModel.findByIdAndDelete(productId)
        } catch (error) {
            return error
        }
    }

    updateProduct = async (pid, campo) => {
        try {
            return await productsModel.findByIdAndUpdate(pid, {$set: campo})
        } catch (error) {
            return error
        }
    }

}