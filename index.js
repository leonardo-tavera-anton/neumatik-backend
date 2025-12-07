import express from "express";
import pool from "./db.js"; // Importa la conexión a la DB
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from 'multer';
// Se añade la configuración de Multer para poder recibir archivos (imágenes).
dotenv.config();


// Configuración de Multer para poder recibir archivos (imágenes).
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
const PORT = process.env.PORT || 3000;



// IMPORTANTE DE SEGURIDAD
const JWT_SECRET = process.env.JWT_SECRET || 'mi_clave_secreta_super_segura_2025';

// ------------------------
// MIDDLEWARE
// ------------------------

// --- CONFIGURACIÓN DE CORS (Cross-Origin Resource Sharing) ---
const allowedOrigins = [
  'https://neumatik-frontend.web.app', // Dominio de producción
  'http://localhost:8080',            // Local
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
    // SIMPLIFICACIÓN: Se elimina 'es_vendedor'
    const { nombre, apellido, correo, contrasena, telefono } = req.body; // Permite la comunicacion con el front si no hay esto no se podra registrar

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

        // SIMPLIFICACIÓN: Se elimina 'es_vendedor' de la consulta
        const newUserQuery = `INSERT INTO usuarios (nombre, apellido, correo, contrasena_hash, telefono, creado_en, ultima_conexion) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING *;`;
        
        // SIMPLIFICACIÓN: Se elimina 'es_vendedor' de los parámetros
        const newUserResult = await pool.query(newUserQuery, [
            nombre,
            apellido,
            correo,
            hashedPassword,
            telefono,
        ]);

        const newUser = newUserResult.rows[0];

        // SIMPLIFICACIÓN: Se elimina 'esVendedor' del token
        const token = jwt.sign(
            { id: newUser.id, correo: newUser.correo },
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

        // SIMPLIFICACIÓN: Se elimina 'esVendedor' del token
        const token = jwt.sign(
            { id: user.id, correo: user.correo },
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
        // SIMPLIFICACIÓN: Se elimina 'es_vendedor' de la consulta
        const result = await pool.query(
            'SELECT id, nombre, apellido, correo, telefono, ultima_conexion FROM usuarios WHERE id = $1',
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
        // SIMPLIFICACIÓN: Se elimina 'es_vendedor' de la cláusula RETURNING
        const updateQuery = `
            UPDATE usuarios 
            SET nombre = $1, apellido = $2, telefono = $3 
            WHERE id = $4 
            RETURNING id, nombre, apellido, correo, telefono, ultima_conexion;
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
                p.id AS publicacion_id, p.id_vendedor, p.precio, p.condicion, p.stock, p.ubicacion_ciudad, 
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
// === ENDPOINT PARA ELIMINAR UNA PUBLICACIÓN (PROTEGIDO) ===
// =======================================================
app.delete('/api/publicaciones/:id', verificarToken, async (req, res) => {
    const { id } = req.params; // ID de la publicación a eliminar
    const id_usuario_actual = req.user.id; // ID del usuario que hace la petición

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Verificar que el usuario es el dueño de la publicación
        const publicacionResult = await client.query('SELECT id_vendedor, id_producto FROM publicaciones WHERE id = $1', [id]);
        if (publicacionResult.rows.length === 0) {
            // Si no se encuentra, consideramos que ya está borrada.
            return res.status(200).json({ message: 'Publicación no encontrada, puede que ya haya sido eliminada.' });
        }
        if (publicacionResult.rows[0].id_vendedor !== id_usuario_actual) {
            return res.status(403).json({ message: 'No tienes permiso para eliminar esta publicación.' });
        }
        const id_producto = publicacionResult.rows[0].id_producto;

        // 2. Eliminar registros dependientes (fotos)
        await client.query('DELETE FROM fotos_publicacion WHERE id_publicacion = $1', [id]);

        // 3. Eliminar la publicación
        await client.query('DELETE FROM publicaciones WHERE id = $1', [id]);

        // 4. Eliminar el producto asociado (si no es usado por otras publicaciones)
        await client.query('DELETE FROM productos WHERE id = $1', [id_producto]);

        await client.query('COMMIT');
        res.status(200).json({ message: 'Publicación eliminada exitosamente.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error al eliminar la publicación:", err);
        res.status(500).json({ message: 'Error interno del servidor al eliminar la publicación.' });
    } finally {
        client.release();
    }
});

// =======================================================
// === ENDPOINT SEGURO PARA ANÁLISIS CON IA (SEPARADO DEL DE CREAR) ===
// =======================================================
app.post('/api/ia/analizar-imagen', verificarToken, upload.single('image'), async (req, res) => {
    // 1. Verificamos que se haya subido una imagen.
    if (!req.file) {
        return res.status(400).json({ message: 'No se proporcionó ninguna imagen.' });
    }

    try {
        // 2. Importamos y configuramos la IA de Google.
        const { GoogleGenerativeAI } = await import('@google/generative-ai'); //dependencia en el package.json y en el pub del front
        //aqui usamos la clave segura guardada en las variables de entorno de Railway lo estare guardando no toquen ni copien pq google reconoce y bloquea.
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);//GEMINI_API_KEY es la variable de entorno donde se guarda la clave de API de Gemini
        const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

        // 3. Preparamos la imagen y el prompt.
        const imagePart = {
            inlineData: {
                data: req.file.buffer.toString('base64'),
                mimeType: req.file.mimetype,
            },
        };

        //tremendo prompt para analisis de las fotos
        const prompt = "Eres un experto en reconocimiento de autopartes. Tu misión es ser **extremadamente observador**. Proporciona tu análisis en español, dividido en dos secciones separadas por una línea horizontal '---'.\n\n" +
            "Análisis de la Autoparte:\n" +
            "Crea una lista de datos clave usando Markdown. Incluye únicamente los siguientes puntos:\n" +
            "- Marca: (La marca de la pieza, si es visible y si no buscalo en internet debes mostrarlo).\n" +
            "- Nombre de la pieza: (Ej: Pastilla de freno, Filtro de aceite).\n" +
            "- Número de Parte (OEM): (Si es visible o claramente deducible).\n" +
            "- Condición estimada: (Nuevo, Usado, Desgastado).\n" +
            "- Compatibilidad: (Menciona marcas o modelos de vehículos compatibles si se puede deducir).\n" +
            "Instrucción clave: Si no puedes determinar un dato, OMITE la línea correspondiente. No des explicaciones.\n\n" +
            "---\n\n" +
            "Detalles de la Imagen:\n" +
            "Describe a grandes rasgos los siguientes aspectos fotográficos:\n" +
            "- Calidad: (Ej: Nítida, Borrosa, Bien iluminada, Oscura).\n" +
            "- Ángulo: (Ej: Frontal, Lateral, Cenital).\n" +
            "- Fondo: (Describe brevemente el fondo de la imagen).";

        // 4. Hacemos la petición a la API de Gemini.
        const result = await model.generateContent([prompt, imagePart]);
        const response = await result.response;
        const text = response.text();

        // 5. Devolvemos el resultado a la app de Flutter.
        res.json({ analysis: text });

    } catch (error) {
        console.error('Error en el análisis con IA:', error);
        // Verificamos si el error es por la clave de API.
        if (error.message && error.message.includes('API key not valid')) {
            return res.status(500).json({ message: 'La clave de API de IA en el servidor no es válida.' });
        }
        res.status(500).json({ message: 'Error interno del servidor al procesar la imagen con IA.' });
    }
});

// =======================================================
// === ENDPOINT DE IA PARA AUTOCOMPLETAR FORMULARIO (NUEVO) ===
// =======================================================
app.post('/api/ia/analizar-para-crear', verificarToken, upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No se proporcionó ninguna imagen.' });
    }

    try {
        const { GoogleGenerativeAI } = await import('@google/generative-ai');
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

        const imagePart = {
            inlineData: {
                data: req.file.buffer.toString('base64'),
                mimeType: req.file.mimetype,
            },
        };

        // --- ESTE ES EL NUEVO PROMPT ---
        const prompt = "Eres un asistente experto para vendedores de autopartes en la plataforma Neumatik. Tu objetivo es analizar la imagen de una autoparte y extraer la información necesaria para pre-rellenar un formulario de venta. Proporciona tu análisis en español, en formato 'clave: valor'.\n\n" +
            "Incluye únicamente los siguientes puntos:\n" +
            "- Nombre de la pieza: (El nombre más común y comercial para la pieza).\n" +
            "- Número de Parte (OEM): (Si es visible o claramente deducible. Si no, omite esta línea).\n" +
            "- Categoría: (Elige UNA de las siguientes opciones: Frenos, Suspensión y Dirección, Motor, Filtros, Sistema Eléctrico, Carrocería, Neumáticos y Ruedas. Si no estás seguro, elige la más probable).\n" +
            "- Condición estimada: (Elige UNA de las siguientes opciones: Nuevo, Usado, Reacondicionado).\n" +
            "- Descripción corta: (Genera una descripción breve y atractiva de 1-2 frases para la venta y recuerda eres el mejor mecanico conocer de todo debes buscar en internet y siempre menciona la marca del producto y si no puedes reconocer abstente tambien menciona medida o tipo investiga en la web).\n" +
            "- Precio estimado (S/): (Estima un precio de venta en Soles Peruanos (S/). Si no estás seguro, proporciona un rango, ej: 150 - 200. Si es imposible de estimar, omite la línea).\n\n" +
            "**Instrucción clave:** No incluyas ninguna otra información, explicación o saludo. Solo la lista de datos.";

        const result = await model.generateContent([prompt, imagePart]);
        const response = await result.response;
        const text = response.text();

        res.json({ analysis: text });

    } catch (error) {
        console.error('Error en el análisis para crear publicación:', error);
        res.status(500).json({ message: 'Error interno del servidor al procesar la imagen con IA.' });
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

// =======================================================
// === ENDPOINTS PARA GESTIÓN DE PEDIDOS (ÓRDENES) ===
// =======================================================

// --- ENDPOINT PARA CREAR UN NUEVO PEDIDO (PROTEGIDO) ---
app.post('/api/pedidos', verificarToken, async (req, res) => {
    const id_comprador = req.user.id;
    const { items, total, direccion_envio } = req.body;

    if (!items || !Array.isArray(items) || items.length === 0 || !total || !direccion_envio) {
        return res.status(400).json({ message: 'Datos del pedido incompletos (items, total, direccion_envio).' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const ordenQuery = `
            INSERT INTO ordenes (id_comprador, total, estado_orden, direccion_envio) 
            VALUES ($1, $2, 'Pendiente', $3) 
            RETURNING id, fecha_orden;
        `;
        const ordenResult = await client.query(ordenQuery, [id_comprador, total, direccion_envio]);
        const nuevaOrden = ordenResult.rows[0];
        const id_orden_nueva = nuevaOrden.id;

        for (const item of items) {
            const subtotal = item.cantidad * item.precio;

            // CORRECCIÓN CRÍTICA: Se añade ::UUID para convertir el string al tipo de dato correcto para PostgreSQL.
            const stockCheck = await client.query('SELECT stock FROM publicaciones WHERE id = $1::UUID FOR UPDATE', [item.id_publicacion]);
            if (stockCheck.rows.length === 0 || stockCheck.rows[0].stock < item.cantidad) {
                throw new Error(`Stock insuficiente para el producto ID ${item.id_publicacion}.`);
            }

            const detalleQuery = `
                INSERT INTO detalles_orden (id_orden, id_publicacion, cantidad, precio_unitario, subtotal) 
                VALUES ($1, $2::UUID, $3, $4, $5);
            `;
            await client.query(detalleQuery, [id_orden_nueva, item.id_publicacion, item.cantidad, item.precio, subtotal]);

            const stockUpdateQuery = `
                UPDATE publicaciones SET stock = stock - $1 WHERE id = $2::UUID;
            `;
            await client.query(stockUpdateQuery, [item.cantidad, item.id_publicacion]);
        }

        await client.query('COMMIT');
        res.status(201).json({
            message: 'Pedido creado exitosamente.',
            pedido: {
                id: id_orden_nueva,
                fecha: nuevaOrden.fecha_orden,
                total: total,
            }
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error en la transacción al crear pedido:", err.stack);
        res.status(500).json({ message: err.message || 'Error interno del servidor al crear el pedido.' });
    } finally {
        client.release();
    }
});


// --- ENDPOINT PARA OBTENER EL HISTORIAL DE PEDIDOS DE UN USUARIO (PROTEGIDO) ---
app.get('/api/pedidos', verificarToken, async (req, res) => {
    const id_usuario = req.user.id;

    try {
        // Consulta para obtener las órdenes del usuario
        const ordenesQuery = `
            SELECT 
                o.id, 
                o.fecha_orden as fecha, 
                o.total,
                u.nombre as usuario_nombre,
                u.correo as usuario_correo
            FROM ordenes o
            JOIN usuarios u ON o.id_usuario = u.id
            WHERE o.id_usuario = $1
            ORDER BY o.fecha_orden DESC;
        `;
        const ordenesResult = await pool.query(ordenesQuery, [id_usuario]);
        let ordenes = ordenesResult.rows;

        // Para cada orden, obtener sus items
        for (let i = 0; i < ordenes.length; i++) {
            const detallesQuery = `
                SELECT 
                    d.cantidad, 
                    d.precio_unitario as precio, 
                    p.nombre_parte 
                FROM detalles_orden d
                JOIN publicaciones pub ON d.id_publicacion = pub.id
                JOIN productos p ON pub.id_producto = p.id
                WHERE d.id_orden = $1;
            `;
            const detallesResult = await pool.query(detallesQuery, [ordenes[i].id]);
            ordenes[i].items = detallesResult.rows;
        }

        res.json(ordenes);

    } catch (err) {
        console.error("Error al obtener el historial de pedidos:", err.stack);
        res.status(500).json({ message: 'Error interno del servidor al obtener el historial.' });
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