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
app.use(cors()); 
app.use(express.json());

// Middleware para verificar el token (para rutas protegidas)
const verificarToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token.' });
    }

    // El header es típicamente "Bearer <token>"
    const token = authHeader.split(' ')[1]; 
    if (!token) {
        return res.status(401).json({ error: 'Formato de token inválido.' });
    }

    try {
        // Verifica y decodifica el token usando la clave secreta
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Adjuntamos los datos del usuario al request
        next(); // Continuamos a la ruta
    } catch (err) {
        console.error("Error de verificación de token:", err);
        return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
};

/**
 * Función de Saneamiento: Convierte valores NULL de la DB a String vacío ("")
 * Requerido para evitar errores de tipo en Flutter/Dart.
 * @param {object} user - El objeto usuario devuelto por la consulta de PostgreSQL
 * @returns {object} Objeto de usuario saneado
 */
const sanearUsuarioParaFlutter = (user) => {
    return {
        id: user.id,
        nombre: user.nombre,
        // Convertir NULL a ""
        apellido: user.apellido || "", 
        correo: user.correo,
        // Convertir NULL a ""
        telefono: user.telefono || "", 
        es_vendedor: user.es_vendedor,
        // Convertir NULL o Date a String 
        ultima_conexion: user.ultima_conexion ? new Date(user.ultima_conexion).toISOString() : "", 
    };
};


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
            <li><strong>POST /api/auth/login</strong> (Ruta de Inicio de Sesión)</li>
            <li><strong>GET /api/usuario/perfil</strong> (Ruta Protegida - Requiere JWT)</li> 
        </ul>
        <p>*2025 - Desarrollado por Leonardo Tavera Anton*</p>
    `);
});


// -------------------------------------------------------
// ENDPOINT DE REGISTRO DE USUARIO (POST /api/registro)
// -------------------------------------------------------
app.post('/api/registro', async (req, res) => {
    const { nombre, apellido, correo, contrasena, telefono, es_vendedor } = req.body;

    if (!correo || !contrasena || !nombre) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: correo, contraseña y nombre.' });
    }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(contrasena, saltRounds);

        // 1. Verificar si el usuario ya existe
        const userCheck = await pool.query('SELECT id FROM usuarios WHERE correo = $1', [correo]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ error: 'El correo electrónico ya está registrado.' });
        }

        // 2. Insertar nuevo usuario.
        // CORRECCIÓN CLAVE: "ultima_conexion" usado en lugar de "ultima_sesion"
        const newUserQuery = `INSERT INTO usuarios (nombre, apellido, correo, contrasena_hash, telefono, es_vendedor, creado_en, ultima_conexion) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) RETURNING id, nombre, apellido, correo, telefono, es_vendedor, ultima_conexion;`;
        const newUserResult = await pool.query(newUserQuery, [
            nombre,
            apellido || null, 
            correo,
            hashedPassword, 
            telefono || null,
            es_vendedor || false, 
        ]);

        const newUser = newUserResult.rows[0];
        
        // 3. GENERAR EL JSON WEB TOKEN (JWT)
        const token = jwt.sign(
            { id: newUser.id, correo: newUser.correo, esVendedor: newUser.es_vendedor },
            JWT_SECRET,
            { expiresIn: '7d' } 
        );

        // 4. Sanear y devolver respuesta (201 Created)
        const perfil = sanearUsuarioParaFlutter(newUser);
        
        res.status(201).json({
            usuario: perfil,
            token: token, 
            mensaje: 'Usuario registrado exitosamente.',
        });

    } catch (err) {
        console.error("Error al registrar usuario:", err.stack);
        res.status(500).json({ error: 'Error interno del servidor al procesar el registro.' });
    }
});

// -------------------------------------------------------
// ENDPOINT DE INICIO DE SESIÓN (POST /api/auth/login)
// -------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: correo y contraseña.' });
    }

    try {
        // 1. Buscar usuario y obtener hash, incluyendo ultima_conexion
        const userResult = await pool.query(
            'SELECT id, nombre, apellido, correo, telefono, es_vendedor, contrasena_hash, ultima_conexion FROM usuarios WHERE correo = $1', 
            [correo]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales inválidas (correo o contraseña incorrectos).' });
        }

        let user = userResult.rows[0];
        
        // 2. Comparar la contraseña ingresada con el hash almacenado
        const isPasswordValid = await bcrypt.compare(contrasena, user.contrasena_hash);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Credenciales inválidas (correo o contraseña incorrectos).' });
        }

        // 3. Contraseña válida, generar JWT
        const token = jwt.sign(
            { id: user.id, correo: user.correo, esVendedor: user.es_vendedor },
            JWT_SECRET,
            { expiresIn: '7d' } 
        );

        // 4. Actualizar ultima_conexion.
        // CORRECCIÓN CLAVE: "ultima_conexion" usado en lugar de "ultima_sesion"
        await pool.query('UPDATE usuarios SET ultima_conexion = NOW() WHERE id = $1', [user.id]);
        
        // 5. SANEAR DATOS para evitar el error de Flutter (null no es subtype of Map)
        const perfil = sanearUsuarioParaFlutter(user);

        res.json({
            token: token,
            usuario: perfil, // Retornamos el objeto saneado
            mensaje: 'Inicio de sesión exitoso. Bienvenido.'
        });

    } catch (err) {
        console.error("Error al iniciar sesión:", err.stack);
        res.status(500).json({ error: 'Error interno del servidor al procesar el inicio de sesión.' });
    }
});

// -------------------------------------------------------
// ENDPOINT PROTEGIDO DE EJEMPLO (Solo accesible con un JWT válido)
// -------------------------------------------------------
app.get('/api/usuario/perfil', verificarToken, async (req, res) => {
    // req.user contiene los datos decodificados del token (id, correo, esVendedor)
    try {
        const userId = req.user.id;
        const result = await pool.query(
            // CORRECCIÓN CLAVE: "ultima_conexion" usado en lugar de "ultima_sesion"
            'SELECT id, nombre, apellido, correo, telefono, es_vendedor, ultima_conexion FROM usuarios WHERE id = $1', 
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        // Sanear el perfil
        const user = result.rows[0];
        const perfil = sanearUsuarioParaFlutter(user);
        
        res.json({ 
            perfil: perfil,
            mensaje: "Datos de perfil obtenidos exitosamente con JWT."
        });
    } catch (err) {
        console.error("Error al obtener perfil:", err.stack);
        res.status(500).json({ error: 'Error al cargar los datos del perfil.' });
    }
});


// -------------------------------------------------------
// ENDPOINT PRINCIPAL PARA EL FRONTEND DE FLUTTER (Listado - Aún es público)
// -------------------------------------------------------
app.get('/api/publicaciones_autopartes', async (req, res) => {
    try {
        const queryText = `SELECT p.id AS publicacion_id, p.precio, p.condicion, p.stock, p.ubicacion_ciudad, p.creado_en AS fecha_publicacion, pr.nombre_parte, pr.numero_oem, u.nombre AS vendedor_nombre, u.apellido AS vendedor_apellido, c.nombre_categoria, (SELECT url FROM fotos_publicacion WHERE id_publicacion = p.id AND es_principal = TRUE LIMIT 1) AS foto_principal_url, ia.validacion_exitosa AS ia_verificado FROM publicaciones p JOIN productos pr ON p.id_producto = pr.id JOIN categorias c ON pr.id_categoria = c.id_categoria JOIN usuarios u ON p.id_vendedor = u.id LEFT JOIN analisis_ia ia ON p.id = ia.id_publicacion WHERE p.estado_publicacion = 'Activa' ORDER BY p.creado_en DESC;`;
        
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