import express from "express";
import pool from "./db.js"; // Importa la conexión a la DB
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// 🛑 ¡IMPORTANTE DE SEGURIDAD! 
const JWT_SECRET = process.env.JWT_SECRET || 'mi_clave_secreta_super_segura_2025';

// ------------------------
// MIDDLEWARE
// ------------------------

// --- CONFIGURACIÓN DE CORS (Cross-Origin Resource Sharing) ---
const allowedOrigins = [
  'https://neumatik-frontend.web.app', // Tu futuro dominio de producción
  'http://localhost:8080',            // El propio backend (si aplica)
  'http://localhost',
  'http://127.0.0.1',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.some(allowed => origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por la política de CORS'));
    }
  },
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

// Middleware para verificar el token (para rutas protegidas)
const verificarToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'Acceso denegado. No se proporcionó token.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Formato de token inválido.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.error("Error de verificación de token:", err);
        return res.status(403).json({ message: 'Token inválido o expirado.' });
    }
};

// ------------------------
// MENÚ INICIO (Ruta Raíz)
// ------------------------
app.get("/", (req, res) => {
    res.send(`
        <h1>Backend Neumatik (Autopartes)</h1>
        <p>Este es el backend para la aplicación de venta de autopartes Neumatik.</p>
        <h3>Rutas de la API:</h3>
        <ul>
            <li>GET /api/publicaciones_autopartes (Listado principal)</li>
            <li>GET /api/publicaciones/:id (Detalle de una publicación)</li>
            <li>POST /api/registro (Registro de Usuarios)</li>
            <li>POST /api/auth/login (Inicio de Sesión)</li>
            <li>GET /api/usuario/perfil (Perfil de usuario - Protegida)</li>
            <li>PUT /api/usuario/perfil (Actualizar perfil - Protegida)</li>
            <li>POST /api/publicaciones (Crear publicación - Protegida)</li>
        </ul>
        <p>*2025 - Desarrollado por Leonardo Tavera Anton*</p>
    `);
});


// -------------------------------------------------------
// ENDPOINT DE REGISTRO DE USUARIO (POST /api/registro)
// -------------------------------------------------------
app.post('/api/registro', async (req, res) => {
    const { nombre, apellido, correo, contrasena, telefono, es_vendedor } = req.body;

    if (!correo || !contrasena || !nombre || !apellido) {
        return res.status(400).json({ message: 'Faltan campos obligatorios: nombre, apellido, correo y contraseña.' });
    }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(contrasena, saltRounds);

        const userCheck = await pool.query('SELECT id FROM usuarios WHERE correo = $1', [correo]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        }

        const newUserQuery = `INSERT INTO usuarios (nombre, apellido, correo, contrasena_hash, telefono, es_vendedor, creado_en, ultima_conexion) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) RETURNING *;`;
        
        const newUserResult = await pool.query(newUserQuery, [
            nombre,
            apellido,
            correo,
            hashedPassword,
            telefono,
            es_vendedor || false,
        ]);

        const newUser = newUserResult.rows[0];

        const token = jwt.sign(
            { id: newUser.id, correo: newUser.correo, esVendedor: newUser.es_vendedor },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            usuario: newUser,
            token: token,
            message: 'Usuario registrado exitosamente.',
        });

    } catch (err) {
        console.error("Error al registrar usuario:", err.message);
        if (err.constraint) {
            return res.status(400).json({ message: `Error de base de datos: ${err.detail}` });
        }
        res.status(500).json({ message: 'Error interno del servidor al procesar el registro.' });
    }
});

// -------------------------------------------------------
// ENDPOINT DE INICIO DE SESIÓN (POST /api/auth/login)
// -------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ message: 'Faltan campos obligatorios: correo y contraseña.' });
    }

    try {
        const userResult = await pool.query(
            'SELECT * FROM usuarios WHERE correo = $1',
            [correo]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).send('Credenciales inválidas (correo o contraseña incorrectos).');
        }

        const user = userResult.rows[0];
        const isPasswordValid = await bcrypt.compare(contrasena, user.contrasena_hash);

        if (!isPasswordValid) {
            return res.status(401).send('Credenciales inválidas (correo o contraseña incorrectos).');
        }

        const token = jwt.sign(
            { id: user.id, correo: user.correo, esVendedor: user.es_vendedor },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        await pool.query('UPDATE usuarios SET ultima_conexion = NOW() WHERE id = $1', [user.id]);

        res.json({
            token: token,
            usuario: user,
            message: 'Inicio de sesión exitoso. Bienvenido.'
        });

    } catch (err) {
        console.error("Error al iniciar sesión:", err.stack);
        res.status(500).json({ message: 'Error interno del servidor al procesar el inicio de sesión.' });
    }
});

// -------------------------------------------------------
// ENDPOINT PROTEGIDO PARA OBTENER PERFIL
// -------------------------------------------------------
app.get('/api/usuario/perfil', verificarToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await pool.query(
            'SELECT id, nombre, apellido, correo, telefono, es_vendedor, ultima_conexion FROM usuarios WHERE id = $1',
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }

        const user = result.rows[0];
        
        res.json({
            perfil: user,
            message: "Datos de perfil obtenidos exitosamente con JWT."
        });
    } catch (err) {
        console.error("Error al obtener perfil:", err.stack);
        res.status(500).json({ message: 'Error al cargar los datos del perfil.' });
    }
});

// =======================================================
// === ENDPOINT NUEVO PARA ACTUALIZAR EL PERFIL DEL USUARIO (PROTEGIDO) ===
// =======================================================
app.put('/api/usuario/perfil', verificarToken, async (req, res) => {
    const userId = req.user.id;
    const { nombre, apellido, telefono } = req.body;

    // Validación básica
    if (!nombre || !apellido) {
        return res.status(400).json({ message: 'El nombre y el apellido son obligatorios.' });
    }

    try {
        const updateQuery = `
            UPDATE usuarios 
            SET nombre = $1, apellido = $2, telefono = $3 
            WHERE id = $4 
            RETURNING id, nombre, apellido, correo, telefono, es_vendedor, ultima_conexion;
        `;
        
        const result = await pool.query(updateQuery, [
            nombre,
            apellido,
            telefono || '', // Usar string vacío si el teléfono es nulo o no se envía
            userId
        ]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado para actualizar.' });
        }

        const updatedUser = result.rows[0];
        
        res.json({
            perfil: updatedUser,
            message: "Perfil actualizado exitosamente."
        });

    } catch (err) {
        console.error("Error al actualizar el perfil:", err.stack);
        res.status(500).json({ message: 'Error interno del servidor al actualizar el perfil.' });
    }
});


// -------------------------------------------------------
// ENDPOINT PARA CREAR UNA NUEVA PUBLICACIÓN (PROTEGIDO)
// -------------------------------------------------------
app.post('/api/publicaciones', verificarToken, async (req, res) => {
    const id_vendedor = req.user.id;
    const {
        nombre_parte, numero_oem, id_categoria, precio,
        condicion, stock, ubicacion_ciudad, descripcion_corta, foto_url,
    } = req.body;

    if (!nombre_parte || !id_categoria || !precio || !condicion || !stock || !ubicacion_ciudad) {
        return res.status(400).json({ message: 'Faltan campos obligatorios para crear la publicación.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const productoQuery = `
            INSERT INTO productos (id_categoria, nombre_parte, numero_oem, descripcion_larga)
            VALUES ($1, $2, $3, $4) RETURNING id;`;
        const productoResult = await client.query(productoQuery, [
            id_categoria, nombre_parte, numero_oem || '', '',
        ]);
        const id_producto_nuevo = productoResult.rows[0].id;

        const publicacionQuery = `
            INSERT INTO publicaciones (id_vendedor, id_producto, precio, stock, condicion, descripcion_corta, ubicacion_ciudad, estado_publicacion)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'Activa') RETURNING id;`;
        const publicacionResult = await client.query(publicacionQuery, [
            id_vendedor, id_producto_nuevo, precio, stock,
            condicion, descripcion_corta || '', ubicacion_ciudad,
        ]);
        const id_publicacion_nueva = publicacionResult.rows[0].id;

        if (foto_url) {
            const fotoQuery = `
                INSERT INTO fotos_publicacion (id_publicacion, url, es_principal)
                VALUES ($1, $2, TRUE);`;
            await client.query(fotoQuery, [id_publicacion_nueva, foto_url]);
        }

        await client.query('COMMIT');
        res.status(201).json({
            message: 'Publicación creada exitosamente.',
            publicacionId: id_publicacion_nueva,
            productoId: id_producto_nuevo,
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error en la transacción al crear publicación:", err.stack);
        res.status(500).json({ message: 'Error interno del servidor al crear la publicación.' });
    } finally {
        client.release();
    }
});

// -------------------------------------------------------
// ENDPOINT PARA LISTAR TODAS LAS PUBLICACIONES
// -------------------------------------------------------
app.get('/api/publicaciones_autopartes', async (req, res) => {
    try {
        const queryText = `
            SELECT 
                p.id AS publicacion_id, p.precio, p.condicion, p.stock, p.ubicacion_ciudad, 
                p.creado_en AS fecha_publicacion, pr.nombre_parte, pr.numero_oem, 
                u.nombre AS vendedor_nombre, u.apellido AS vendedor_apellido, c.nombre_categoria, 
                (SELECT url FROM fotos_publicacion WHERE id_publicacion = p.id AND es_principal = TRUE LIMIT 1) AS foto_principal_url, 
                ia.validacion_exitosa AS ia_verificado 
            FROM publicaciones p 
            JOIN productos pr ON p.id_producto = pr.id 
            JOIN categorias c ON pr.id_categoria = c.id_categoria 
            JOIN usuarios u ON p.id_vendedor = u.id 
            LEFT JOIN analisis_ia ia ON p.id = ia.id_publicacion 
            WHERE p.estado_publicacion = 'Activa' 
            ORDER BY p.creado_en DESC;`;
        
        const result = await pool.query(queryText);
        res.json(result.rows);
    } catch (err) {
        console.error("Error al ejecutar la consulta de publicaciones de autopartes:", err);
        res.status(500).json({ message: 'Error interno del servidor al consultar la base de datos.' });
    }
});

// =======================================================
// === ENDPOINT PARA DETALLE DE PUBLICACIÓN ===
// =======================================================
app.get('/api/publicaciones/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const queryText = `
            SELECT 
                p.id AS publicacion_id, p.precio, p.condicion, p.stock, p.ubicacion_ciudad, 
                p.creado_en AS fecha_publicacion, p.descripcion_corta,
                pr.nombre_parte, pr.numero_oem, 
                u.nombre AS vendedor_nombre, u.apellido AS vendedor_apellido, c.nombre_categoria, 
                (SELECT url FROM fotos_publicacion WHERE id_publicacion = p.id AND es_principal = TRUE LIMIT 1) AS foto_principal_url, 
                ia.validacion_exitosa AS ia_verificado 
            FROM publicaciones p 
            JOIN productos pr ON p.id_producto = pr.id 
            JOIN categorias c ON pr.id_categoria = c.id_categoria 
            JOIN usuarios u ON p.id_vendedor = u.id 
            LEFT JOIN analisis_ia ia ON p.id = ia.id_publicacion 
            WHERE p.id = $1;`;
        
        const result = await pool.query(queryText, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Publicación no encontrada.' });
        }

        res.json(result.rows[0]);

    } catch (err) {
        console.error("Error al obtener el detalle de la publicación:", err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// =======================================================
// === ENDPOINT PARA ACTUALIZAR UNA PUBLICACIÓN (PROTEGIDO) ===
// =======================================================
app.put('/api/publicaciones/:id', verificarToken, async (req, res) => {
    const { id } = req.params; // ID de la publicación a editar
    const id_usuario_actual = req.user.id; // ID del usuario que hace la petición

    const {
        nombre_parte, id_categoria, precio,
        condicion, stock, ubicacion_ciudad, numero_oem, descripcion_corta,
    } = req.body;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Verificar que el usuario es el dueño de la publicación
        const publicacionResult = await client.query('SELECT id_vendedor, id_producto FROM publicaciones WHERE id = $1', [id]);
        if (publicacionResult.rows.length === 0) {
            throw new Error('Publicación no encontrada.');
        }
        if (publicacionResult.rows[0].id_vendedor !== id_usuario_actual) {
            return res.status(403).json({ message: 'No tienes permiso para editar esta publicación.' });
        }
        const id_producto = publicacionResult.rows[0].id_producto;

        // 2. Actualizar la tabla 'productos'
        const productoUpdateQuery = `UPDATE productos SET nombre_parte = $1, numero_oem = $2, id_categoria = $3 WHERE id = $4;`;
        await client.query(productoUpdateQuery, [nombre_parte, numero_oem, id_categoria, id_producto]);

        // 3. Actualizar la tabla 'publicaciones'
        const publicacionUpdateQuery = `UPDATE publicaciones SET precio = $1, stock = $2, condicion = $3, descripcion_corta = $4, ubicacion_ciudad = $5 WHERE id = $6;`;
        await client.query(publicacionUpdateQuery, [precio, stock, condicion, descripcion_corta, ubicacion_ciudad, id]);

        await client.query('COMMIT');
        res.status(200).json({ message: 'Publicación actualizada exitosamente.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error al actualizar la publicación:", err);
        res.status(500).json({ message: 'Error interno del servidor al actualizar la publicación.' });
    } finally {
        client.release();
    }
});


// =======================================================
// === ENDPOINT PARA OBTENER LAS PUBLICACIONES DE UN USUARIO (PROTEGIDO) ===
// =======================================================
app.get('/api/usuario/publicaciones', verificarToken, async (req, res) => {
    const id_vendedor = req.user.id; // Obtenemos el ID del usuario desde el token verificado

    try {
        const queryText = `
            SELECT 
                p.id AS publicacion_id, p.precio, p.condicion, p.stock, p.ubicacion_ciudad, 
                p.creado_en AS fecha_publicacion, pr.nombre_parte, pr.numero_oem, 
                u.nombre AS vendedor_nombre, u.apellido AS vendedor_apellido, c.nombre_categoria, 
                (SELECT url FROM fotos_publicacion WHERE id_publicacion = p.id AND es_principal = TRUE LIMIT 1) AS foto_principal_url, 
                ia.validacion_exitosa AS ia_verificado 
            FROM publicaciones p 
            JOIN productos pr ON p.id_producto = pr.id 
            JOIN categorias c ON pr.id_categoria = c.id_categoria 
            JOIN usuarios u ON p.id_vendedor = u.id 
            LEFT JOIN analisis_ia ia ON p.id = ia.id_publicacion 
            WHERE p.id_vendedor = $1
            ORDER BY p.creado_en DESC;`;
        
        const result = await pool.query(queryText, [id_vendedor]);
        res.json(result.rows);

    } catch (err) {
        console.error("Error al obtener las publicaciones del usuario:", err);
        res.status(500).json({ message: 'Error interno del servidor al consultar tus publicaciones.' });
    }
});


// ------------------------
// RUTAS DE TABLAS SIMPLES (PARA DEBUG)
// ------------------------
const tablas = [
    "usuarios", "categorias", "marcas_vehiculo", "modelos_vehiculo",
    "productos", "compatibilidad_producto", "publicaciones", "fotos_publicacion",
    "ordenes", "detalles_orden", "reviews", "analisis_ia"
];

tablas.forEach(tabla => {
    app.get(`/${tabla}`, async (req, res) => {
      try {
        const result = await pool.query(`SELECT * FROM ${tabla}`);
        res.json(result.rows);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: `Error al obtener ${tabla}` });
      }
    });
});


// ------------------------
// INICIAR SERVIDOR
// ------------------------
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
