require('dotenv').config();
const mysql = require('mysql2/promise'); // Utilisation de mysql2/promise pour async/await
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Configuration de la connexion MySQL
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'admin',
  password: process.env.DB_PASSWORD || 'azerty',
  database: process.env.DB_NAME || 'bdusers'
};

// Middleware pour vérifier l'authentification
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ error: 'Authentification requise' });
  }

  const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const [nom_utilisateur, mot_de_passe] = credentials;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      'SELECT * FROM USERS WHERE NOM_UTILISATEUR = ?', 
      [nom_utilisateur]
    );
    
    if (rows.length === 0 || !(await bcrypt.compare(mot_de_passe, rows[0].MOT_DE_PASSE))) {
      return res.status(401).json({ error: 'Authentification échouée' });
    }

    req.user = rows[0];
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
}

// Initialisation de la base de données
async function initializeDatabase() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS USERS (
        id INT AUTO_INCREMENT PRIMARY KEY,
        NOM_UTILISATEUR VARCHAR(255) NOT NULL UNIQUE,
        MOT_DE_PASSE VARCHAR(255) NOT NULL
      )
    `);
    
    console.log('Base de données initialisée');
    await connection.end();
  } catch (err) {
    console.error('Erreur initialisation DB:', err);
    process.exit(1);
  }
}

// Routes
app.post('/users', async (req, res) => {
  try {
    const { nom_utilisateur, mot_de_passe } = req.body;
    if (!nom_utilisateur || !mot_de_passe) {
      return res.status(400).json({ error: 'Nom utilisateur et mot de passe requis' });
    }

    const hashedPassword = await bcrypt.hash(mot_de_passe, 10);
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      'INSERT INTO USERS (NOM_UTILISATEUR, MOT_DE_PASSE) VALUES (?, ?)',
      [nom_utilisateur, hashedPassword]
    );
    
    res.status(201).json({ id: result.insertId, nom_utilisateur });
    await connection.end();
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(409).json({ error: 'Nom d\'utilisateur déjà utilisé' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
});

app.get('/users', authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      'SELECT id, NOM_UTILISATEUR FROM USERS'
    );
    res.json(rows);
    await connection.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Démarrer le serveur
const PORT = process.env.PORT || 3000;
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Serveur REST API en écoute sur le port ${PORT}`);
  });
});