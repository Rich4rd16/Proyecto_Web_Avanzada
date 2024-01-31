import { comparePassword, hashPassword } from "../helpers/authHelper.js";
import userModel from "../models/userModel.js";
import JWT from "jsonwebtoken";

export const registerController = async (req, res) => {
    try {
        const {name, email, password, phone, address} =req.body
        //Validación
        if(!name){
            return res.send({error: 'El nombre es requerido'});
        }
        if(!email){
            return res.send({error: 'El email es requerido'});
        }
        if(!password){
            return res.send({error: 'La contraseña es requerida'});
        }
        if(!phone){
            return res.send({error: 'El telefono no es requerido'});
        }
        if(!address){
            return res.send({error: 'La dirección es requerido'});
        }

        //Chequea usuario
        const exisitingUser = await userModel.findOne({email})

        //Existe usuario
        if(exisitingUser){
            return res.status(200).send({
                success:true,
                message:'Ya existe este usuario'
            })
        }

        //Registro de usuario
        const hashedPassword = await hashPassword(password)

        //Guardar
        const user = await new userModel({name, email, phone, address, password:hashedPassword}).save();

        res.status(201).send({
            success:true,
            message:'Usuario registrado satisfactoriamente',
            user
        })

    } catch (error) {
        console.log(error)
        res.status(500).send({
            success:false,
            message: 'Error en el Registro',
            error
        })
    }
};

//POST LOGIN
export const loginController =  async (req, res) => {
    try {
        const {email, password} = req.body
        //validation
        if (!email || !password) {
            return res.status(404).send({
                success: false,
                message: "Invalid email or password",
            });
        }
        //CHEKEANDO USUARIO
        const user = await userModel.findOne({email})
        if (!user){
            return res.status(404).send({
                success:false,
                message:'El email no esta registrado'
            })
        }
        const match = await comparePassword(password,user.password)
        if (!match){
            return res.status(200).send({
                success:false,
                message:'Contraseña Invalida'
            })
        }

        //token
        const token = await JWT.sign({ _id: user._id}, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        res.status(200).send({
            success:true,
            message:'Inicio de sesión satisfactorio',
            user:{
                name: user.name,
                email: user.email,
                phone: user.phone,
                address: user.address,
            },
            token,
        });
    } catch (error) {
        console.log(error)
        res.status(500).send({
            success:false,
            message:'Error en el inicio de sesión',
            error,
        });
    }
};

//test controller
export const testController = (req, res) =>{
    try {
        res.send("Ruta protegida");
    } catch (error) {
        console.log(error);
        res.send({error});
    }
};