import pkg from "pg";
const { Pool } = pkg; // Uso la destructuring de Pool como solicitaste
import dotenv from "dotenv";

dotenv.config();

// Configuración del Pool de Conexiones de PostgreSQL
const pool = new Pool({
    // Usa la variable de entorno DATABASE_URL proporcionada por Railway
    connectionString: process.env.DATABASE_URL,
    
    // Configuración adicional requerida para ambientes como Railway que usan SSL
    ssl: {
        rejectUnauthorized: false // Obligatorio en Railway y otros servicios cloud
    }
});

pool.on('connect', () => {
    console.log('Conectado a la base de datos PostgreSQL.');
});

pool.on('error', (err) => {
    console.error('Error inesperado en el cliente PostgreSQL inactivo:', err.stack);
    // Este listener es vital para detectar problemas de conexión en producción.
});

export default pool;