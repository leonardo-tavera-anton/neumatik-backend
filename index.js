import express from "express";
import pool from "./db.js"; // Importa la conexión a la DB
import dotenv from "dotenv";
import cors from "cors"; // <--- 1. Importa el módulo CORS
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------------
// MIDDLEWARE
// ------------------------
app.use(cors()); // <--- 2. Habilita CORS para permitir solicitudes desde Flutter Web
app.use(express.json());

// ------------------------
// MENÚ INICIO
// ------------------------
app.get("/", (req, res) => {
  res.send(`
    <h1>Backend Neumatik (Autopartes)</h1>
    Este es el backend para la aplicación de venta de autopartes Neumatik.<br/>
    Desarrollado con Node.js, Express y PostgreSQL.<br/><br/>
    <h3>Rutas de la API (para Flutter):</h3>
    <ul>
        <li><a href="/api/publicaciones_autopartes">/api/publicaciones_autopartes</a> (Listado principal de la App)</li>
    </ul>
    <h3>Rutas Simples de Tabla:</h3>
    <ul>
        <li><a href="/usuarios">/usuarios</a></li> (<em>lista de usuarios</em>)
        <li><a href="/categorias">/categorias</a></li> (</em>categorias de autopartes</em>)
        <li><a href="/marcas_vehiculo">/Marcas</a></li> (<em>marcas de vehiculos</em>)
        <li><a href="/modelos_vehiculo">/Modelos</a></li> (<em>modelos de vehiculos</em>)
        <li><a href="/productos">/productos</a></li> (<em>todas las autopartes</em>)
        <li><a href="/compatibilidad_producto">/Compatibilidad</a></li> (<em>compatibilidad con productos</em>)
        <li><a href="/publicaciones">/publicaciones</a></li> (<em>todas las publicaciones</em>)
        <li><a href="/fotos_publicacion">/Fotos</a></li> (<em>fotos de las publicaciones</em>)
        <li><a href="/ordenes">/Ordenes</a></li> (<em>osea el carrito de compra</em>)
        <li><a href="/detalles_orden">/Detalles Orden</a></li> (<em>detalles del carrito</em>)
        <li><a href="/reviews">/Reviews</a></li> (<em>reseñas de usuarios</em>)    
        <li><a href="/analisis_ia">/Analisis IA</a></li> (<em>resultados del análisis IA</em>)
        
    </ul>
    <p>Haga click en cualquier enlace para ver los datos por tabla</p>
    (<p>Desarrollado por leo 2025</p>)
 `);
});

// -------------------------------------------------------
// ENDPOINT PRINCIPAL PARA EL FRONTEND DE FLUTTER
// Obtiene el listado de publicaciones activas con toda la data relacionada.
// -------------------------------------------------------
app.get('/api/publicaciones_autopartes', async (req, res) => {
    try {
        const queryText = `
            SELECT
                p.id AS publicacion_id,
                p.precio,
                p.condicion,
                p.stock,
                p.ubicacion_ciudad,
                p.creado_en AS fecha_publicacion,
                
                pr.nombre_parte,
                pr.numero_oem,
                
                u.nombre AS vendedor_nombre,
                u.apellido AS vendedor_apellido,
                
                c.nombre_categoria,
                
                -- Subconsulta para obtener la URL de la foto principal
                (
                    SELECT url 
                    FROM fotos_publicacion 
                    WHERE id_publicacion = p.id AND es_principal = TRUE 
                    LIMIT 1
                ) AS foto_principal_url,
                
                -- Verifica si el análisis IA fue exitoso
                ia.validacion_exitosa AS ia_verificado
            FROM
                publicaciones p
            JOIN
                productos pr ON p.id_producto = pr.id
            JOIN
                categorias c ON pr.id_categoria = c.id_categoria
            JOIN
                usuarios u ON p.id_vendedor = u.id
            LEFT JOIN
                analisis_ia ia ON p.id = ia.id_publicacion -- LEFT JOIN para publicaciones que aún no han sido analizadas
            WHERE
                p.estado_publicacion = 'Activa'
            ORDER BY p.creado_en DESC;
        `;
        
        const result = await pool.query(queryText);
        res.json(result.rows);
    } catch (err) {
        console.error("Error al ejecutar la consulta de publicaciones de autopartes:", err);
        res.status(500).json({ error: 'Error interno del servidor al consultar la base de datos.' });
    }
});


// ------------------------
// RUTAS DE TABLAS SIMPLES (MANTENEMOS LAS TUYAS ORIGINALES)
// ------------------------
const tablas = [
  "usuarios",
  "categorias",
  "marcas_vehiculo",
  "modelos_vehiculo",
  "productos",
  "compatibilidad_producto",
  "publicaciones",
  "fotos_publicacion",
  "ordenes",
  "detalles_orden",
  "reviews",
  "analisis_ia"
];

tablas.forEach(tabla => {
  app.get(`/${tabla}`, async (req, res) => {
    try {
      const result = await pool.query(`SELECT * FROM ${tabla}`);
      res.json(result.rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: `Error al obtener ${tabla}` });
    }
  });
});


// ------------------------
// INICIAR SERVIDOR
// ------------------------
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});