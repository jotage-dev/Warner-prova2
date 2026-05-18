const express = require("express");
const http = require("http");
const winston = require("winston");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
  ),
  transports: [
    new winston.transports.File({ filename: "audit.log" }),
    new winston.transports.Console(),
  ],
});

app.post("/log", (req, res) => {
  const data = req.body;

  if (data.event === "auth_failure" && data.attempts > 3) {
    logger.warn(
      `ALERTA: Possível ataque de Força Bruta detectado no email: ${data.email}`,
    );
    io.emit("security_alert", {
      type: "BRUTE_FORCE",
      message: `Muitas tentativas falhas para ${data.email}`,
    });
  }

  if (data.event === "privilege_escalation_attempt") {
    logger.error(
      `ALERTA: Tentativa de escalação de privilégio por: ${data.email}`,
    );
    io.emit("security_alert", {
      type: "PRIVILEGE_ESCALATION",
      message: `Usuário ${data.email} tentou acessar rota restrita.`,
    });
  }

  if (
    data.event === "sql_injection_detected" &&
    data.payload?.includes("' OR")
  ) {
    logger.error(
      `CRÍTICO: Possível SQL Injection detectado no payload: ${data.payload}`,
    );
    io.emit("security_alert", {
      type: "SQL_INJECTION",
      message: `Payload suspeito detectado: ${data.payload}`,
    });
  }

  logger.info("Auditoria", data);
  io.emit("new_log", data); 
  res.sendStatus(200);
});

server.listen(3005, () => console.log("SIEM/Monitor Service na porta 3005"));
