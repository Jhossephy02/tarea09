const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// Configuración de la base de datos SQLite
const db = new sqlite3.Database('./motos.db', (err) => {
    if (err) {
        console.error('❌ Error al conectar con la base de datos:', err);
    } else {
        console.log('✅ Conectado a la base de datos SQLite');
        inicializarDB();
    }
});

// JWT Secret
const JWT_SECRET = 'tu_secreto_super_seguro_para_motos_123';

// Inicializar base de datos y crear tablas
function inicializarDB() {
    db.serialize(() => {
        // Tabla de usuarios
        db.run(`CREATE TABLE IF NOT EXISTS usuarios (
            id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_completo TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            telefono TEXT,
            fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP,
            ultimo_acceso DATETIME,
            estado TEXT DEFAULT 'activo' CHECK(estado IN ('activo', 'inactivo', 'suspendido')),
            rol TEXT DEFAULT 'cliente' CHECK(rol IN ('cliente', 'vendedor', 'admin'))
        )`);

        // Tabla de marcas
        db.run(`CREATE TABLE IF NOT EXISTS marcas (
            id_marca INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            pais_origen TEXT,
            logo_url TEXT
        )`);

        // Tabla de categorías
        db.run(`CREATE TABLE IF NOT EXISTS categorias (
            id_categoria INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            descripcion TEXT
        )`);

        // Tabla de motos
        db.run(`CREATE TABLE IF NOT EXISTS motos (
            id_moto INTEGER PRIMARY KEY AUTOINCREMENT,
            id_marca INTEGER,
            id_categoria INTEGER,
            modelo TEXT NOT NULL,
            año INTEGER NOT NULL,
            precio REAL NOT NULL,
            kilometraje INTEGER DEFAULT 0,
            color TEXT,
            cilindrada INTEGER,
            tipo_motor TEXT,
            transmision TEXT DEFAULT 'manual' CHECK(transmision IN ('manual', 'automatica')),
            estado TEXT NOT NULL CHECK(estado IN ('nueva', 'usada')),
            descripcion TEXT,
            imagen_principal TEXT,
            stock INTEGER DEFAULT 1,
            destacada INTEGER DEFAULT 0,
            fecha_agregada DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_marca) REFERENCES marcas(id_marca),
            FOREIGN KEY (id_categoria) REFERENCES categorias(id_categoria)
        )`);

        // Tabla de cotizaciones
        db.run(`CREATE TABLE IF NOT EXISTS cotizaciones (
            id_cotizacion INTEGER PRIMARY KEY AUTOINCREMENT,
            id_usuario INTEGER,
            id_moto INTEGER,
            mensaje TEXT,
            telefono_contacto TEXT,
            fecha_cotizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
            estado TEXT DEFAULT 'pendiente' CHECK(estado IN ('pendiente', 'respondida', 'cerrada')),
            FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario),
            FOREIGN KEY (id_moto) REFERENCES motos(id_moto)
        )`);

        // Tabla de favoritos
        db.run(`CREATE TABLE IF NOT EXISTS favoritos (
            id_favorito INTEGER PRIMARY KEY AUTOINCREMENT,
            id_usuario INTEGER,
            id_moto INTEGER,
            fecha_agregado DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario),
            FOREIGN KEY (id_moto) REFERENCES motos(id_moto),
            UNIQUE(id_usuario, id_moto)
        )`);

        // Insertar datos de prueba
        insertarDatosPrueba();
    });
}

// Insertar datos de prueba
function insertarDatosPrueba() {
    // Verificar si ya hay datos
    db.get('SELECT COUNT(*) as count FROM marcas', (err, row) => {
        if (row.count === 0) {
            console.log('📦 Insertando datos de prueba...');

            // Marcas
            const marcas = [
                ['Honda', 'Japón', ''],
                ['Yamaha', 'Japón', ''],
                ['Suzuki', 'Japón', ''],
                ['Kawasaki', 'Japón', ''],
                ['Bajaj', 'India', ''],
                ['BMW', 'Alemania', ''],
                ['Ducati', 'Italia', ''],
                ['KTM', 'Austria', ''],
                ['Harley-Davidson', 'Estados Unidos', '']
            ];

            marcas.forEach(marca => {
                db.run('INSERT INTO marcas (nombre, pais_origen, logo_url) VALUES (?, ?, ?)', marca);
            });

            // Categorías
            const categorias = [
                ['Deportiva', 'Motos de alta velocidad y rendimiento'],
                ['Cruiser', 'Motos de paseo y comodidad'],
                ['Scooter', 'Motos automáticas urbanas'],
                ['Touring', 'Motos para viajes largos'],
                ['Off-Road', 'Motos para terrenos difíciles'],
                ['Naked', 'Motos sin carenado deportivas'],
                ['Adventure', 'Motos todoterreno para aventura']
            ];

            categorias.forEach(cat => {
                db.run('INSERT INTO categorias (nombre, descripcion) VALUES (?, ?)', cat);
            });

            // Motos de prueba
            setTimeout(() => {
                const motos = [
                    [1, 1, 'CBR 600RR', 2023, 12500.00, 0, 'Rojo', 600, '4 cilindros', 'manual', 'nueva', 'Deportiva de alto rendimiento con tecnología de punta', 'https://images.unsplash.com/photo-1558981806-ec527fa84c39?w=800', 5, 1],
                    [1, 6, 'CB 190R', 2024, 3200.00, 0, 'Negro', 190, 'Monocilíndrico', 'manual', 'nueva', 'Perfecta para la ciudad, económica y confiable', 'https://images.unsplash.com/photo-1568772585407-9361f9bf3a87?w=800', 10, 1],
                    [2, 1, 'YZF-R6', 2023, 13000.00, 0, 'Azul', 600, '4 cilindros', 'manual', 'nueva', 'Supersport japonesa con diseño agresivo', 'https://images.unsplash.com/photo-1609630875171-b1321377ee65?w=800', 3, 1],
                    [2, 3, 'NMAX 155', 2024, 2800.00, 0, 'Gris', 155, 'Monocilíndrico', 'automatica', 'nueva', 'Scooter moderna con gran espacio de almacenamiento', 'https://images.unsplash.com/photo-1568772585407-9361f9bf3a87?w=800', 8, 1],
                    [3, 1, 'GSX-R750', 2022, 11500.00, 2500, 'Blanco', 750, '4 cilindros', 'manual', 'usada', 'En excelente estado, mantenimiento al día', 'https://images.unsplash.com/photo-1558980664-769d59546b3d?w=800', 2, 0],
                    [4, 1, 'Ninja 650', 2023, 9800.00, 0, 'Verde', 650, 'Bicilíndrico', 'manual', 'nueva', 'Deportiva media cilindrada, perfecta para empezar', 'https://images.unsplash.com/photo-1568772585407-9361f9bf3a87?w=800', 4, 1],
                    [5, 6, 'Pulsar NS200', 2024, 2500.00, 0, 'Rojo', 200, 'Monocilíndrico', 'manual', 'nueva', 'Naked deportiva, relación calidad-precio excelente', 'https://images.unsplash.com/photo-1558981806-ec527fa84c39?w=800', 12, 1],
                    [6, 1, 'F 850 GS', 2023, 18500.00, 0, 'Naranja', 850, 'Bicilíndrico', 'manual', 'nueva', 'Adventure premium alemana para cualquier terreno', 'https://images.unsplash.com/photo-1558981852-426c6c22a060?w=800', 2, 1],
                    [7, 1, 'Panigale V4', 2023, 32000.00, 0, 'Rojo', 1100, 'V4', 'manual', 'nueva', 'Superbike italiana de competición', 'https://images.unsplash.com/photo-1609630875171-b1321377ee65?w=800', 1, 1],
                    [1, 2, 'Shadow 750', 2022, 8500.00, 5000, 'Negro', 750, 'V2', 'manual', 'usada', 'Cruiser clásica en perfecto estado', 'https://images.unsplash.com/photo-1558980664-769d59546b3d?w=800', 3, 0],
                    [2, 6, 'MT-09', 2024, 11200.00, 0, 'Azul', 890, 'Triple', 'manual', 'nueva', 'Naked triple cilindros con carácter único', 'https://images.unsplash.com/photo-1558981806-ec527fa84c39?w=800', 3, 1],
                    [8, 5, 'Duke 390', 2024, 6500.00, 0, 'Naranja', 390, 'Monocilíndrico', 'manual', 'nueva', 'Naked agresiva austríaca, pura diversión', 'https://images.unsplash.com/photo-1568772585407-9361f9bf3a87?w=800', 6, 1]
                ];

                motos.forEach(moto => {
                    db.run(`INSERT INTO motos (id_marca, id_categoria, modelo, año, precio, kilometraje, color, 
                            cilindrada, tipo_motor, transmision, estado, descripcion, imagen_principal, stock, destacada) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, moto);
                });

                console.log('✅ Datos de prueba insertados correctamente');
            }, 500);
        }
    });
}

// Middleware para verificar token
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(403).json({ error: 'Token no proporcionado' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Token inválido' });
        }
        req.userId = decoded.id;
        next();
    });
};

// ============================================
// RUTAS DE AUTENTICACIÓN
// ============================================

// Registro de usuario
app.post('/api/auth/register', async (req, res) => {
    try {
        const { nombre_completo, email, password, telefono } = req.body;
        
        if (!nombre_completo || !email || !password) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }
        
        // Verificar si el email ya existe
        db.get('SELECT id_usuario FROM usuarios WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Error al verificar email' });
            }
            
            if (row) {
                return res.status(400).json({ error: 'El email ya está registrado' });
            }
            
            // Hash de la contraseña
            const passwordHash = await bcrypt.hash(password, 10);
            
            // Insertar usuario
            db.run(
                'INSERT INTO usuarios (nombre_completo, email, password_hash, telefono) VALUES (?, ?, ?, ?)',
                [nombre_completo, email, passwordHash, telefono || null],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Error al registrar usuario' });
                    }
                    
                    res.status(201).json({
                        success: true,
                        message: 'Usuario registrado exitosamente',
                        userId: this.lastID
                    });
                }
            );
        });
        
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: 'Error al registrar usuario' });
    }
});

// Login de usuario
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email y contraseña son requeridos' });
        }
        
        db.get('SELECT * FROM usuarios WHERE email = ? AND estado = "activo"', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Error al buscar usuario' });
            }
            
            if (!user) {
                return res.status(401).json({ error: 'Credenciales inválidas' });
            }
            
            // Verificar contraseña
            const isValidPassword = await bcrypt.compare(password, user.password_hash);
            
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Credenciales inválidas' });
            }
            
            // Actualizar último acceso
            db.run('UPDATE usuarios SET ultimo_acceso = CURRENT_TIMESTAMP WHERE id_usuario = ?', [user.id_usuario]);
            
            // Generar token
            const token = jwt.sign(
                { id: user.id_usuario, email: user.email, rol: user.rol },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({
                success: true,
                message: 'Login exitoso',
                token,
                user: {
                    id: user.id_usuario,
                    nombre: user.nombre_completo,
                    email: user.email,
                    rol: user.rol
                }
            });
        });
        
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

// ============================================
// RUTAS DE MOTOS
// ============================================

// Obtener todas las motos
app.get('/api/motos', (req, res) => {
    const { categoria, marca, precio_min, precio_max, estado, destacadas, buscar } = req.query;
    
    let query = `
        SELECT m.*, ma.nombre as marca_nombre, c.nombre as categoria_nombre
        FROM motos m
        LEFT JOIN marcas ma ON m.id_marca = ma.id_marca
        LEFT JOIN categorias c ON m.id_categoria = c.id_categoria
        WHERE m.stock > 0
    `;
    
    const params = [];
    
    if (categoria) {
        query += ' AND m.id_categoria = ?';
        params.push(categoria);
    }
    
    if (marca) {
        query += ' AND m.id_marca = ?';
        params.push(marca);
    }
    
    if (precio_min) {
        query += ' AND m.precio >= ?';
        params.push(precio_min);
    }
    
    if (precio_max) {
        query += ' AND m.precio <= ?';
        params.push(precio_max);
    }
    
    if (estado) {
        query += ' AND m.estado = ?';
        params.push(estado);
    }
    
    if (destacadas === 'true') {
        query += ' AND m.destacada = 1';
    }
    
    if (buscar) {
        query += ' AND (m.modelo LIKE ? OR m.descripcion LIKE ? OR ma.nombre LIKE ?)';
        const searchTerm = `%${buscar}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }
    
    query += ' ORDER BY m.destacada DESC, m.fecha_agregada DESC';
    
    db.all(query, params, (err, motos) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener motos' });
        }
        
        res.json({
            success: true,
            data: motos,
            total: motos.length
        });
    });
});

// Obtener una moto por ID
app.get('/api/motos/:id', (req, res) => {
    const { id } = req.params;
    
    db.get(`
        SELECT m.*, ma.nombre as marca_nombre, c.nombre as categoria_nombre
        FROM motos m
        LEFT JOIN marcas ma ON m.id_marca = ma.id_marca
        LEFT JOIN categorias c ON m.id_categoria = c.id_categoria
        WHERE m.id_moto = ?
    `, [id], (err, moto) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener moto' });
        }
        
        if (!moto) {
            return res.status(404).json({ error: 'Moto no encontrada' });
        }
        
        res.json({
            success: true,
            data: moto
        });
    });
});

// Crear cotización
app.post('/api/cotizaciones', verificarToken, (req, res) => {
    const { id_moto, mensaje, telefono_contacto } = req.body;
    
    db.run(
        'INSERT INTO cotizaciones (id_usuario, id_moto, mensaje, telefono_contacto) VALUES (?, ?, ?, ?)',
        [req.userId, id_moto, mensaje, telefono_contacto],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Error al crear cotización' });
            }
            
            res.status(201).json({
                success: true,
                message: 'Cotización enviada exitosamente',
                cotizacionId: this.lastID
            });
        }
    );
});

// Agregar a favoritos
app.post('/api/favoritos', verificarToken, (req, res) => {
    const { id_moto } = req.body;
    
    db.run(
        'INSERT INTO favoritos (id_usuario, id_moto) VALUES (?, ?)',
        [req.userId, id_moto],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'La moto ya está en favoritos' });
                }
                return res.status(500).json({ error: 'Error al agregar favorito' });
            }
            
            res.status(201).json({
                success: true,
                message: 'Moto agregada a favoritos'
            });
        }
    );
});

// Obtener favoritos del usuario
app.get('/api/favoritos', verificarToken, (req, res) => {
    db.all(`
        SELECT m.*, ma.nombre as marca_nombre, c.nombre as categoria_nombre
        FROM favoritos f
        JOIN motos m ON f.id_moto = m.id_moto
        LEFT JOIN marcas ma ON m.id_marca = ma.id_marca
        LEFT JOIN categorias c ON m.id_categoria = c.id_categoria
        WHERE f.id_usuario = ?
        ORDER BY f.fecha_agregado DESC
    `, [req.userId], (err, favoritos) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener favoritos' });
        }
        
        res.json({
            success: true,
            data: favoritos
        });
    });
});

// Obtener marcas
app.get('/api/marcas', (req, res) => {
    db.all('SELECT * FROM marcas ORDER BY nombre', (err, marcas) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener marcas' });
        }
        res.json({ success: true, data: marcas });
    });
});

// Obtener categorías
app.get('/api/categorias', (req, res) => {
    db.all('SELECT * FROM categorias ORDER BY nombre', (err, categorias) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener categorías' });
        }
        res.json({ success: true, data: categorias });
    });
});

// Ruta de prueba
app.get('/api/test', (req, res) => {
    res.json({ 
        message: '🏍️ API de MotoStore funcionando correctamente',
        timestamp: new Date().toISOString()
    });
});

// Ruta principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

// Iniciar servidor
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`
    ╔════════════════════════════════════════╗
    ║   🏍️  MOTOSTORE API INICIADA 🏍️       ║
    ╠════════════════════════════════════════╣
    ║  Servidor: http://localhost:${PORT}      ║
    ║  Base de datos: SQLite (motos.db)      ║
    ║  Estado: ✅ Funcionando                 ║
    ╚════════════════════════════════════════╝
    `);
});