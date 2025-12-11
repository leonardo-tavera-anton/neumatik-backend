import pkg from "pg";
const { Pool } = pkg; //usar Pool para manejar conexiones a PostgreSQL
import dotenv from "dotenv";

dotenv.config();

//crear una nueva instancia de Pool con la configuración adecuada
const pool = new Pool({
    //usar la variable de entorno para la cadena de conexión en railway
    connectionString: process.env.DATABASE_URL,
    
    //configuración SSL para conexiones seguras
    ssl: {
        rejectUnauthorized: false //para evitar errores de certificado en entornos gestionados
    }
});

pool.on('connect', () => {
    console.log('Conectado a la base de datos PostgreSQL.');
});

pool.on('error', (err) => {
    console.error('Error inesperado en el cliente PostgreSQL inactivo:', err.stack); //esta funcion informa y maneja errores inesperados
});

export default pool;