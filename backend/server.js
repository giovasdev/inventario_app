const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const path = require('path');

require('dotenv').config(); // Cargar variables de entorno desde .env
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios'); // Para la verificación de reCAPTCHA

const app = express();

app.use(cors());
app.use(express.json());

// --- Configuración de express-session ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'mi_secreto_de_sesion_seguro', // Usa una clave secreta fuerte y guárdala en .env
    resave: false, // No guarda la sesión si no hay cambios
    saveUninitialized: false, // No crea una sesión hasta que se almacena algo
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // Ejemplo: la cookie dura 1 día (en milisegundos)
}));

// Inicializar Passport
app.use(passport.initialize());
app.use(passport.session());

// --- Servir archivos estáticos ---
app.use(express.static(path.join(__dirname, '..', 'frontend'))); 

// Clave secreta para JWT (Mover a .env)
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta_por_defecto'; // <-- MODIFICAR AQUÍ

// --- Variables de Entorno para OAuth y reCAPTCHA ---
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback';
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY; // Clave secreta de reCAPTCHA

// Conexión a MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '75103837',
    database: 'inventario_seguridad_oauth',
    port: 3305
});

db.connect(err => {
    if (err) throw err;
    console.log('Conectado a la base de datos');
});

// Middleware para verificar token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// --- CONFIGURACIÓN DE PASSPORT PARA GOOGLE OAUTH ---
passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
        scope: ['profile', 'email'] // Solicitar el perfil y el correo del usuario
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails[0].value;
            const nombre = profile.displayName;
            const googleId = profile.id;

            // 1. Buscar si el empleado ya existe por correo o google_id
            db.query('SELECT * FROM Empleados WHERE correo = ? OR google_id = ?', [email, googleId], async (err, results) => {
                if (err) return done(err);

                if (results.length > 0) {
                    // El usuario ya existe
                    const existingUser = results[0];
                    // Si el usuario existe pero no tiene google_id (ej. se registró localmente), lo actualizamos
                    if (!existingUser.google_id) {
                        db.query('UPDATE Empleados SET google_id = ? WHERE id_empleado = ?', [googleId, existingUser.id_empleado], (updateErr) => {
                            if (updateErr) return done(updateErr);
                            return done(null, existingUser);
                        });
                    } else {
                        // El usuario ya existe y tiene google_id
                        return done(null, existingUser);
                    }
                } else {
                    const defaultRoleId = 1;

                    db.query('INSERT INTO Empleados (nombre, correo, google_id, id_rol, telefono) VALUES (?, ?, ?, ?, ?)',
                        [nombre, email, googleId, defaultRoleId, 'No especificado'], // El teléfono es un campo NOT NULL
                        (insertErr, result) => {
                            if (insertErr) return done(insertErr);
                            const newUser = {
                                id_empleado: result.insertId,
                                nombre,
                                email,
                                google_id: googleId,
                                id_rol: defaultRoleId,
                                telefono: 'No especificado'
                            };
                            return done(null, newUser);
                        });
                }
            });
        } catch (error) {
            done(error);
        }
    }));

passport.serializeUser((user, done) => {
    done(null, user.id_empleado);
});

passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM Empleados WHERE id_empleado = ?', [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]);
    });
});

// --- RUTAS DE AUTENTICACIÓN OAUTH ---

// Ruta para iniciar la autenticación con Google
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Ruta de callback de Google después de la autenticación
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login.html' }), // Redirige a login si falla
    (req, res) => {
        // Autenticación exitosa, generar JWT y redirigir al frontend
        // req.user contiene la información del usuario de la estrategia de Passport
        const token = jwt.sign({ id: req.user.id_empleado, correo: req.user.correo, id_rol: req.user.id_rol }, JWT_SECRET, { expiresIn: '1h' });


        res.redirect(`/index.html#token=${token}&nombre=${encodeURIComponent(req.user.nombre)}&id_empleado=${req.user.id_empleado}&id_rol=${req.user.id_rol}`);
    }
);

// Ruta para verificar si el usuario está autenticado (opcional, para depuración)
app.get('/auth/google/success', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ message: 'Autenticado con Google', user: req.user });
    } else {
        res.status(401).json({ message: 'No autenticado' });
    }
});

// Registro
app.post('/api/register', (req, res) => {
    const { nombre, correo, telefono, id_rol, contrasena, recaptchaToken } = req.body; // <-- AÑADIR recaptchaToken

    // --- VERIFICACIÓN RECAPTCHA ---
    if (!recaptchaToken) {
        return res.status(400).json({ error: 'Token reCAPTCHA es requerido.' });
    }

    axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`)
        .then(recaptchaRes => {
            const { success, score } = recaptchaRes.data;
            if (!success) { // Para reCAPTCHA v2 (checkbox)
                return res.status(400).json({ error: 'Verificación reCAPTCHA fallida.' });
            }

            // --- CONTINÚA CON LA LÓGICA DE REGISTRO SOLO SI RECAPTCHA ES VÁLIDO ---
            bcrypt.hash(contrasena, 10, (err, hash) => {
                if (err) return res.status(500).json({ error: err.message });

                db.query(
                    'INSERT INTO Empleados (nombre, correo, telefono, id_rol, contrasena_hash) VALUES (?, ?, ?, ?, ?)',
                    [nombre, correo, telefono, id_rol, hash],
                    (err, result) => {
                        if (err) {
                            if (err.code === 'ER_DUP_ENTRY') {
                                return res.status(409).json({ error: 'El correo ya está registrado.' });
                            }
                            return res.status(500).json({ error: err.message });
                        }
                        res.status(201).json({ message: 'Usuario registrado con éxito.' });
                    }
                );
            });
        })
        .catch(error => {
            console.error('Error al verificar reCAPTCHA:', error.response ? error.response.data : error.message);
            res.status(500).json({ error: 'Error interno al verificar reCAPTCHA.' });
        });
});

// Login
app.post('/api/login', (req, res) => {
    const { correo, contrasena, recaptchaToken } = req.body; // <-- AÑADIR recaptchaToken

    // --- VERIFICACIÓN RECAPTCHA ---
    if (!recaptchaToken) {
        return res.status(400).json({ error: 'Token reCAPTCHA es requerido.' });
    }

    axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`)
        .then(recaptchaRes => {
            const { success, score } = recaptchaRes.data;
            if (!success) { // Para reCAPTCHA v2
                return res.status(400).json({ error: 'Verificación reCAPTCHA fallida.' });
            }

            // --- CONTINÚA CON LA LÓGICA DE LOGIN SOLO SI RECAPTCHA ES VÁLIDO ---
            db.query('SELECT * FROM Empleados WHERE correo = ?', [correo], (err, results) => {
                if (err) return res.status(500).json({ error: err.message });
                if (results.length === 0) return res.status(400).json({ error: 'Credenciales inválidas.' });

                const user = results[0];
                // Si el usuario tiene una contraseña local (no OAuth)
                if (user.contrasena_hash) {
                    bcrypt.compare(contrasena, user.contrasena_hash, (err, isMatch) => {
                        if (err) return res.status(500).json({ error: err.message });
                        if (!isMatch) return res.status(400).json({ error: 'Credenciales inválidas.' });

                        const token = jwt.sign({ id: user.id_empleado, correo: user.correo, id_rol: user.id_rol }, JWT_SECRET, { expiresIn: '1h' });
                        // No devolver la contraseña en la respuesta
                        const { contrasena_hash, ...userWithoutPassword } = user;
                        res.json({ token, user: userWithoutPassword });
                    });
                } else {
                    // Si el usuario no tiene contraseña (probablemente registrado via OAuth)
                    // No puede iniciar sesión con contraseña, debe usar OAuth.
                    return res.status(400).json({ error: 'Esta cuenta fue registrada con un proveedor externo. Por favor, inicia sesión usando Google.' });
                }
            });
        })
        .catch(error => {
            console.error('Error al verificar reCAPTCHA:', error.response ? error.response.data : error.message);
            res.status(500).json({ error: 'Error interno al verificar reCAPTCHA.' });
        });
});

// Rutas protegidas
app.get('/api/roles', authenticateToken, (req, res) => db.query('SELECT * FROM Roles', (err, results) => res.json(results)));
app.post('/api/roles', authenticateToken, (req, res) => {
    const { nombre_rol, descripcion } = req.body;
    db.query('INSERT INTO Roles (nombre_rol, descripcion) VALUES (?, ?)', [nombre_rol, descripcion], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_rol: result.insertId, nombre_rol, descripcion });
    });
});
app.put('/api/roles/:id', authenticateToken, (req, res) => {
    const { nombre_rol, descripcion } = req.body;
    console.log('Datos recibidos:', { nombre_rol, descripcion, id: req.params.id }); // Log para depuración
    db.query('UPDATE Roles SET nombre_rol = ?, descripcion = ? WHERE id_rol = ?', [nombre_rol, descripcion, req.params.id], (err) => {
        if (err) {
            console.error('Error en la consulta:', err.message); // Log para errores
            return res.status(500).json({ error: err.message });
        }
        res.json({ id_rol: req.params.id, nombre_rol, descripcion });
    });
});
app.delete('/api/roles/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Roles WHERE id_rol = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Rol eliminado' });
    });
});
app.get('/api/roles/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Roles WHERE id_rol = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Rol no encontrado' });
        res.json(results[0]);
    });
});

app.get('/api/empleados', authenticateToken, (req, res) => db.query('SELECT e.*, r.nombre_rol FROM Empleados e JOIN Roles r ON e.id_rol = r.id_rol', (err, results) => res.json(results)));
app.post('/api/empleados', authenticateToken, (req, res) => {
    const { nombre, correo, telefono, id_rol } = req.body;
    db.query('INSERT INTO Empleados (nombre, correo, telefono, id_rol) VALUES (?, ?, ?, ?)', [nombre, correo, telefono, id_rol], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_empleado: result.insertId, nombre, correo, telefono, id_rol });
    });
});
app.put('/api/empleados/:id', authenticateToken, (req, res) => {
    const { nombre, correo, telefono, id_rol } = req.body;
    db.query('UPDATE Empleados SET nombre = ?, correo = ?, telefono = ?, id_rol = ? WHERE id_empleado = ?', [nombre, correo, telefono, id_rol, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_empleado: req.params.id, nombre, correo, telefono, id_rol });
    });
});
app.delete('/api/empleados/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Empleados WHERE id_empleado = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Empleado eliminado' });
    });
});
app.get('/api/empleados/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT e.*, r.nombre_rol FROM Empleados e JOIN Roles r ON e.id_rol = r.id_rol WHERE e.id_empleado = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Empleado no encontrado' });
        res.json(results[0]);
    });
});

app.get('/api/categorias', authenticateToken, (req, res) => db.query('SELECT * FROM Categorias', (err, results) => res.json(results)));
app.post('/api/categorias', authenticateToken, (req, res) => {
    const { nombre, descripcion } = req.body;
    db.query('INSERT INTO Categorias (nombre, descripcion) VALUES (?, ?)', [nombre, descripcion], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_categoria: result.insertId, nombre, descripcion });
    });
});
app.put('/api/categorias/:id', authenticateToken, (req, res) => {
    const { nombre, descripcion } = req.body;
    db.query('UPDATE Categorias SET nombre = ?, descripcion = ? WHERE id_categoria = ?', [nombre, descripcion, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_categoria: req.params.id, nombre, descripcion });
    });
});
app.delete('/api/categorias/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Categorias WHERE id_categoria = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Categoría eliminada' });
    });
});
app.get('/api/categorias/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Categorias WHERE id_categoria = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Categoría no encontrada' });
        res.json(results[0]);
    });
});

app.get('/api/proveedores', authenticateToken, (req, res) => db.query('SELECT * FROM Proveedores', (err, results) => res.json(results)));
app.post('/api/proveedores', authenticateToken, (req, res) => {
    const { nombre, contacto, telefono, correo } = req.body;
    db.query('INSERT INTO Proveedores (nombre, contacto, telefono, correo) VALUES (?, ?, ?, ?)', [nombre, contacto, telefono, correo], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_proveedor: result.insertId, nombre, contacto, telefono, correo });
    });
});
app.put('/api/proveedores/:id', authenticateToken, (req, res) => {
    const { nombre, contacto, telefono, correo } = req.body;
    db.query('UPDATE Proveedores SET nombre = ?, contacto = ?, telefono = ?, correo = ? WHERE id_proveedor = ?', [nombre, contacto, telefono, correo, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_proveedor: req.params.id, nombre, contacto, telefono, correo });
    });
});
app.delete('/api/proveedores/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Proveedores WHERE id_proveedor = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Proveedor eliminado' });
    });
});
app.get('/api/proveedores/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Proveedores WHERE id_proveedor = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Proveedor no encontrado' });
        res.json(results[0]);
    });
});

app.get('/api/productos', authenticateToken, (req, res) => db.query('SELECT p.*, c.nombre AS categoria, pr.nombre AS proveedor FROM Productos p JOIN Categorias c ON p.id_categoria = c.id_categoria JOIN Proveedores pr ON p.id_proveedor = pr.id_proveedor', (err, results) => res.json(results)));
app.post('/api/productos', authenticateToken, (req, res) => {
    const { nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario } = req.body;
    db.query('INSERT INTO Productos (nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario) VALUES (?, ?, ?, ?, ?, ?)', [nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario], (err, result) => {
        if (err) return res.status (500).json({ error: err.message });
        res.json({ id_producto: result.insertId, nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario });
    });
});
app.put('/api/productos/:id', authenticateToken, (req, res) => {
    const { nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario } = req.body;
    db.query('UPDATE Productos SET nombre = ?, codigo = ?, descripcion = ?, id_categoria = ?, id_proveedor = ?, precio_unitario = ? WHERE id_producto = ?', [nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_producto: req.params.id, nombre, codigo, descripcion, id_categoria, id_proveedor, precio_unitario });
    });
});
app.delete('/api/productos/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Productos WHERE id_producto = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Producto eliminado' });
    });
});
app.get('/api/productos/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT p.*, c.nombre AS categoria, pr.nombre AS proveedor FROM Productos p JOIN Categorias c ON p.id_categoria = c.id_categoria JOIN Proveedores pr ON p.id_proveedor = pr.id_proveedor WHERE p.id_producto = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
        res.json(results[0]);
    });
});

app.get('/api/ubicaciones', authenticateToken, (req, res) => db.query('SELECT * FROM Ubicaciones', (err, results) => res.json(results)));
app.post('/api/ubicaciones', authenticateToken, (req, res) => {
    const { nombre, direccion, tipo } = req.body;
    db.query('INSERT INTO Ubicaciones (nombre, direccion, tipo) VALUES (?, ?, ?)', [nombre, direccion, tipo], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_ubicacion: result.insertId, nombre, direccion, tipo });
    });
});
app.put('/api/ubicaciones/:id', authenticateToken, (req, res) => {
    const { nombre, direccion, tipo } = req.body;
    db.query('UPDATE Ubicaciones SET nombre = ?, direccion = ?, tipo = ? WHERE id_ubicacion = ?', [nombre, direccion, tipo, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_ubicacion: req.params.id, nombre, direccion, tipo });
    });
});
app.delete('/api/ubicaciones/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Ubicaciones WHERE id_ubicacion = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Ubicación eliminada' });
    });
});
app.get('/api/ubicaciones/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Ubicaciones WHERE id_ubicacion = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Ubicación no encontrada' });
        res.json(results[0]);
    });
});

app.get('/api/movimientos', authenticateToken, (req, res) => db.query('SELECT m.*, p.nombre AS producto, u.nombre AS ubicacion, e.nombre AS empleado FROM Movimientos_Inventario m JOIN Productos p ON m.id_producto = p.id_producto JOIN Ubicaciones u ON m.id_ubicacion = u.id_ubicacion JOIN Empleados e ON m.id_empleado = e.id_empleado', (err, results) => res.json(results)));
app.post('/api/movimientos', authenticateToken, (req, res) => {
    const { id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad } = req.body;
    db.query('INSERT INTO Movimientos_Inventario (id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad) VALUES (?, ?, ?, ?, ?)', [id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_movimiento: result.insertId, id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad });
    });
});
app.put('/api/movimientos/:id', authenticateToken, (req, res) => {
    const { id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad } = req.body;
    db.query('UPDATE Movimientos_Inventario SET id_producto = ?, id_ubicacion = ?, id_empleado = ?, tipo_movimiento = ?, cantidad = ? WHERE id_movimiento = ?', [id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id_movimiento: req.params.id, id_producto, id_ubicacion, id_empleado, tipo_movimiento, cantidad });
    });
});
app.delete('/api/movimientos/:id', authenticateToken, (req, res) => {
    db.query('DELETE FROM Movimientos_Inventario WHERE id_movimiento = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Movimiento eliminado' });
    });
});
app.get('/api/movimientos/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT m.*, p.nombre AS producto, u.nombre AS ubicacion, e.nombre AS empleado FROM Movimientos_Inventario m JOIN Productos p ON m.id_producto = p.id_producto JOIN Ubicaciones u ON m.id_ubicacion = u.id_ubicacion JOIN Empleados e ON m.id_empleado = e.id_empleado WHERE m.id_movimiento = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Movimiento no encontrado' });
        res.json(results[0]);
    });
});

app.get('/api/inventario', authenticateToken, (req, res) => db.query('SELECT i.*, p.nombre AS producto, u.nombre AS ubicacion FROM Inventario_Actual i JOIN Productos p ON i.id_producto = p.id_producto JOIN Ubicaciones u ON i.id_ubicacion = u.id_ubicacion', (err, results) => res.json(results)));

app.listen(3000, () => console.log('Servidor corriendo en puerto 3000'));