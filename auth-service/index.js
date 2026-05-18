const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const axios = require("axios");

const app = express();
app.use(express.json());

// 🕵️ MIDDLEWARE ESPIÃO: Mostra EXATAMENTE o que chegou no microsserviço
app.use((req, res, next) => {
  console.log(
    `\n🕵️ [AUTH-SERVICE] Recebeu requisição: ${req.method} ${req.url}`,
  );
  next();
});

const pool = new Pool({
  user: "admin",
  host: process.env.DB_HOST || "postgres",
  database: "fintech_db",
  password: "password",
  port: 5432,
});

// 🛡️ FUNÇÃO RESET DE BANCO: Injeta usuários de teste com hashes 100% confiáveis via Node.js
async function ajustarSenhaNoBanco() {
  try {
    console.log(
      "⏳ [DATABASE] Limpando e reinjetando usuários de teste com Bcrypt...",
    );

    // Limpa a tabela antiga para não duplicar ou manter dados corrompidos
    await pool.query("TRUNCATE TABLE users RESTART IDENTITY CASCADE;");

    // Gera o hash perfeito para a senha '123456'
    const hashPerfeito = await bcrypt.hash("123456", 10);

    // Injeta o Admin e o Usuário Comum diretamente
    await pool.query(
      `INSERT INTO users (name, email, password, role) VALUES 
       ($1, $2, $3, $4),
       ($5, $6, $7, $8);`,
      [
        "Administrador",
        "admin@fintech.com",
        hashPerfeito,
        "admin",
        "Usuario Comum",
        "user@fintech.com",
        hashPerfeito,
        "user",
      ],
    );

    console.log("✅ [DATABASE] Sucesso! Contas prontas para uso:");
    console.log("   -> admin@fintech.com | 123456");
    console.log("   -> user@fintech.com  | 123456");
  } catch (err) {
    console.error("❌ Erro ao inicializar contas no banco:", err.message);
  }
}

// Executa a inicialização 3 segundos após o serviço ligar (tempo para o Postgres estabilizar)
setTimeout(ajustarSenhaNoBanco, 3000);

const failedAttempts = new Map();

// Aceita qualquer uma das duas rotas
app.post(["/login", "/auth/login"], async (req, res) => {
  const { email, password } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  try {
    console.log(`[AUTH-SERVICE] Processando login para: ${email}`);
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      console.log(`❌ Usuário não encontrado: ${email}`);
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // O Bcrypt compara a senha digitada com o hash gerado no banco
    const senhaValida = await bcrypt.compare(password, user.password);

    if (!senhaValida) {
      console.log(`❌ Senha incorreta para o usuário: ${email}`);
      let attempts = (failedAttempts.get(email) || 0) + 1;
      failedAttempts.set(email, attempts);
      axios
        .post(`${process.env.MONITOR_URL}/log`, {
          event: "auth_failure",
          email,
          ip,
          attempts,
        })
        .catch(() => {});
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    failedAttempts.delete(email);
    axios
      .post(`${process.env.MONITOR_URL}/log`, {
        event: "auth_success",
        email,
        ip,
      })
      .catch(() => {});

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );
    res.json({ token, role: user.role });
  } catch (error) {
    console.error("🔥 ERRO:", error.message);
    res.status(500).json({ error: "Erro no servidor", motivo: error.message });
  }
});

// ❌ CAPTURADOR DE 404 CUSTOMIZADO
app.use((req, res) => {
  console.log(
    `❌ [AUTH-SERVICE] Rota ignorada (404). O Gateway mandou: ${req.url}`,
  );
  res.status(404).json({
    error: "Rota não encontrada DENTRO do Auth Service",
    rota_que_o_gateway_mandou: req.url,
  });
});

app.listen(3001, () => console.log("Auth Service na porta 3001"));
