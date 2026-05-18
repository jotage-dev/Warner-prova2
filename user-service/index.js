const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
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

const authorize = (roles = []) => {
  return (req, res, next) => {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token não fornecido" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ error: "Token inválido" });

      if (roles.length && !roles.includes(decoded.role)) {
        axios
          .post(`${process.env.MONITOR_URL}/log`, {
            event: "privilege_escalation_attempt",
            email: decoded.email,
            target_role: roles,
          })
          .catch(() => {});
        return res
          .status(403)
          .json({ error: "Acesso negado: Privilégios insuficientes" });
      }

      req.user = decoded;
      next();
    });
  };
};


app.get(
  ["/vulnerable-search", "/users/vulnerable-search"],
  async (req, res) => {
    const email = req.query.email;
    axios
      .post(`${process.env.MONITOR_URL}/log`, {
        event: "sql_injection_detected",
        payload: email,
      })
      .catch(() => {});

    try {
      const query = `SELECT id, name, email, role FROM users WHERE email='${email}'`;
      const result = await pool.query(query);
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },
);

// 🟢 CENÁRIO 1: PREVENÇÃO DE SQL INJECTION (SEGURO)
app.get(["/secure-search", "/users/secure-search"], async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, role FROM users WHERE email = $1",
      [req.query.email],
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Erro no banco de dados" });
  }
});

app.post(
  ["/admin/pam-session", "/users/admin/pam-session"],
  authorize(["admin"]),
  (req, res) => {
    const sessionToken = jwt.sign(
      { user: req.user.email, access: "database", pam: true },
      process.env.JWT_SECRET,
      { expiresIn: "10m" },
    );

    axios
      .post(`${process.env.MONITOR_URL}/log`, {
        event: "pam_session_created",
        email: req.user.email,
      })
      .catch(() => {});

    res.json({
      message: "Sessão privilegiada temporária criada",
      sessionToken,
    });
  },
);

app.listen(3002, () => console.log("User Service na porta 3002"));
