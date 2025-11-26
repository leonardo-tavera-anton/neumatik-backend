import express from "express";
import pool from "./db.js"; // Importa la conexión a la DB
import dotenv from "dotenv";
import cors from "cors"; 
import bcrypt from "bcrypt"; // Importante para hashear contraseñas

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------------
// MIDDLEWARE
// ------------------------
app.use(cors()); 
app.use(express.json());

// ------------------------
// MENÚ INICIO (Ruta Raíz)
// ------------------------
app.get("/", (req, res) => {
  res.send(`
    <h1>Backend Neumatik (Autopartes)</h1>
    Este es el backend para la aplicación de venta de autopartes Neumatik.<br/>
    Desarrollado con Node.js, Express y PostgreSQL.<br/><br/>
    <h3>Rutas de la API (para Flutter):</h3>
    <ul>
        <li><a href="/api/publicaciones_autopartes">/api/publicaciones_autopartes</a> (Listado principal de la App)</li>
        <li><strong>POST /api/registro</strong> (Ruta de Registro de Usuarios)</li> 
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
    <p>*2025 - Desarrollado por Leonardo Tavera Anton*</p>
 `);
});


// -------------------------------------------------------
// ENDPOINT DE REGISTRO DE USUARIO (POST /api/registro)
// -------------------------------------------------------
app.post('/api/registro', async (req, res) => {
    // Las claves deben ser 'nombre', 'apellido', 'correo', 'contrasena', 'telefono', 'es_vendedor'
    const { nombre, apellido, correo, contrasena, telefono, es_vendedor } = req.body;

    // 1. Validación básica de campos requeridos
    if (!correo || !contrasena || !nombre) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: correo, contraseña y nombre.' });
    }

    try {
        // 2. Hash de la contraseña (ESENCIAL para seguridad)
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(contrasena, saltRounds);

        // 3. Verificar si el usuario ya existe
        const userCheck = await pool.query('SELECT id FROM usuarios WHERE correo = $1', [correo]);
        if (userCheck.rows.length > 0) {
            // Devuelve JSON 409 Conflict. Flutter lo capturará como error.
            return res.status(409).json({ error: 'El correo electrónico ya está registrado.' });
        }

        // 4. Insertar nuevo usuario
        const newUserQuery = `
            INSERT INTO usuarios (nombre, apellido, correo, contrasena_hash, telefono, es_vendedor, creado_en, ultima_sesion)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
            RETURNING id, nombre, apellido, correo, telefono, es_vendedor;
        `;
        const newUserResult = await pool.query(newUserQuery, [
            nombre,
            apellido || null, 
            correo,
            hashedPassword, // Almacena el hash, no la contraseña original
            telefono || null,
            es_vendedor || false, 
        ]);

        const newUser = newUserResult.rows[0];

        // 5. Registro exitoso (201 Created). Devolvemos el objeto del usuario y un token.
        // La estructura de respuesta es vital para el modelo UsuarioAutenticado en Flutter
        res.status(201).json({
            usuario: newUser,
            token: `TOKEN_PARA_USUARIO_${newUser.id}`, // Token simulado
            mensaje: 'Usuario registrado exitosamente.',
        });

    } catch (err) {
        console.error("Error al registrar usuario:", err.stack);
        // Error interno del servidor (500)
        res.status(500).json({ error: 'Error interno del servidor al procesar el registro.' });
    }
});


// -------------------------------------------------------
// ENDPOINT PRINCIPAL PARA EL FRONTEND DE FLUTTER (Listado)
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
                analisis_ia ia ON p.id = ia.id_publicacion
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
// RUTAS DE TABLAS SIMPLES 
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