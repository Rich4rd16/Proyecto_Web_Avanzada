// Importa la biblioteca bcrypt
import bcrypt from "bcrypt";

// Función asincrónica para generar el hash de una contraseña
export const hashPassword = async (password) => {
    try {
        // Define el número de rondas de sal utilizado por bcrypt
        const saltRounds = 10;

        // Genera el hash de la contraseña utilizando bcrypt
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Devuelve el hash resultante
        return hashedPassword;
    } catch (error) {
        // Maneja cualquier error que pueda ocurrir durante la generación del hash
        console.log(error);
    }
};

// Función asincrónica para comparar una contraseña sin procesar con un hash almacenado
export const comparePassword = async (password, hashedPassword) => {
    // Utiliza bcrypt para comparar la contraseña sin procesar con el hash almacenado
    return bcrypt.compare(password, hashedPassword);
};
