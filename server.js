//Se pone el import debido a agregar ""type": "module"," en el package.json 
import express from 'express';
import colors from'colors';
import dotenv from'dotenv';
import morgan from 'morgan';
import connectDB from './config/db.js';
import authRoutes from './routes/authRoute.js'

//configure env
dotenv.config();

// database config
connectDB();

//rest object
const app = express();

//middlewares
app.use(express.json());
app.use(morgan('dev'));

//routes
app.use("/auth", authRoutes);

//rest api
app.get('/', (req, res) =>{
    res.send({
        message:'Bienvenido al Ecommerce'
    });
});

//PORT
const PORT = process.env.PORT || 8080 ;

//run listen
app.listen(PORT, () =>{
    console.log(`El server esta corriendo en ${PORT}`.bgCyan.white);
});