const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');

const app = express();
const SECRET_KEY = 'tu_clave_secreta';

// Middlewares
app.use(bodyParser.json());

// Almacenamiento de usuarios en memoria (para el ejemplo)
const usuarios = {};

// Configuración de límite de tasa global
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 10, // Limita cada IP a 10 peticiones por minuto
});
app.use(globalLimiter);

// Limitadores específicos para rutas
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 5, // Limita a 5 intentos de login por minuto
});

const registerLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 3, // Limita a 3 intentos de registro por minuto
});

// Ruta principal
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Ruta de inicio de sesión con Rate Limiting
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (usuarios[username] && usuarios[username] === password) {
    const accessToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ accessToken, refreshToken });
  } else {
    res.status(401).json({ msg: "Usuario o contraseña incorrectos" });
  }
});

// Ruta de registro con Rate Limiting
app.post('/register', registerLimiter, (req, res) => {
  const { username, password } = req.body;

  if (usuarios[username]) {
    res.status(400).json({ msg: "El usuario ya fue creado" });
  } else {
    usuarios[username] = password;
    res.status(201).json({ msg: "Usuario registrado exitosamente" });
  }
});

// Middleware de autenticación para rutas protegidas
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Ruta protegida con límite de tasa específico
const protectedLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 20, // Limita a 20 peticiones por hora
});

app.get('/protected', authenticateJWT, protectedLimiter, (req, res) => {
  res.json({ logged_in_as: req.user.username });
});

// Manejador de errores de límite de tasa
app.use((req, res) => {
  res.status(429).json({ error: "Límite de peticiones excedido. Por favor, intenta de nuevo más tarde." });
});

app.listen(3000, () => {
  console.log('Servidor en ejecución en http://localhost:3000');
});
