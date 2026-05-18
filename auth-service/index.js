const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const axios = require("axios");

const app = express();
app.use(express.json());

const pool = new Pool({
  user: "admin",
  host: process.env.DB_HOST,
  database: "fintech_db",
  password: "password",
  port: 5432,
});

const failedAttempts = new Map(); // Simulação simples de controle em memória para o SIEM

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      // SIEM: Lógica de Força Bruta
      let attempts = (failedAttempts.get(email) || 0) + 1;
      failedAttempts.set(email, attempts);

      axios
        .post(`${process.env.MONITOR_URL}/log`, {
          event: "auth_failure",
          email,
          ip,
          attempts,
        })
        .catch(() => console.log("Monitor offline"));

      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    failedAttempts.delete(email); // Reseta tentativas
    axios
      .post(`${process.env.MONITOR_URL}/log`, {
        event: "auth_success",
        email,
        ip,
      })
      .catch(() => console.log("Monitor offline"));

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );
    res.json({ token, role: user.role });
  } catch (error) {
    res.status(500).json({ error: "Erro no servidor" });
  }
});

app.listen(3001, () => console.log("Auth Service na porta 3001"));
