const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 4001;
const JWT_SECRET = 'charutoapp-super-secreto-mvp'; // depois vamos para env

app.use(cors());
app.use(express.json());

// "Banco" em memória para MVP (será trocado por DB depois)
const users = [];

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'auth', time: new Date().toISOString() });
});

// Registro de usuário
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Nome, e-mail e senha são obrigatórios.' });
    }

    const existing = users.find(u => u.email === email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'E-mail já cadastrado.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length + 1,
      name,
      email: email.toLowerCase(),
      passwordHash,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);

    return res.status(201).json({
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      createdAt: newUser.createdAt,
    });
  } catch (err) {
    console.error('REGISTER_ERROR', err);
    return res.status(500).json({ error: 'Erro interno ao registrar usuário.' });
  }
});

// Login de usuário
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    }

    const user = users.find(u => u.email === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('LOGIN_ERROR', err);
    return res.status(500).json({ error: 'Erro interno ao fazer login.' });
  }
});

app.listen(PORT, () => {
  console.log(`Auth service rodando em http://localhost:${PORT}`);
});
