require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Autenticación con Google
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const nombre = profile.displayName;
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      const insert = await pool.query(
        'INSERT INTO usuarios (nombre, email, username, password, rol) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [nombre, email, `google_${profile.id}`, '', 'usuario']
      );
      return done(null, insert.rows[0]);
    }

    return done(null, result.rows[0]);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Rutas
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/registro', (req, res) => res.sendFile(path.join(__dirname, 'public', 'registro.html')));
app.get('/reset', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset.html')));

app.post('/registro', async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    'INSERT INTO usuarios (username, email, password, rol) VALUES ($1, $2, $3, $4)',
    [username, email, hash, 'usuario']
  );
  res.redirect('/login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);

  if (result.rows.length === 0) return res.send('Usuario no encontrado');
  const valid = await bcrypt.compare(password, result.rows[0].password);
  if (!valid) return res.send('Contraseña incorrecta');

  req.session.usuario = result.rows[0];
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Google OAuth rutas
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  }
);

// Recuperación de contraseña
app.post('/reset', async (req, res) => {
  const { email } = req.body;
  const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
  if (result.rows.length === 0) return res.send('No existe ese usuario');

  const nuevaClave = Math.random().toString(36).substring(2, 10);
  const hash = await bcrypt.hash(nuevaClave, 10);
  await pool.query('UPDATE usuarios SET password = $1 WHERE email = $2', [hash, email]);

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.CORREO_FROM,
      pass: process.env.CORREO_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.CORREO_FROM,
    to: email,
    subject: 'Recuperación de contraseña',
    text: `Tu nueva contraseña es: ${nuevaClave}`
  });

  res.send('Nueva contraseña enviada al correo.');
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor iniciado en http://localhost:${PORT}`));
