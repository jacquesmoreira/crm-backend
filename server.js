const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const jwt          = require("jsonwebtoken");
const bcrypt       = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
require("dotenv").config();

const app    = express();
const prisma = new PrismaClient();
const PORT   = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "crm_secret_2026";

app.use(helmet());
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// ── JWT MIDDLEWARE ─────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Token inválido" }); }
};

// ── AUTH ───────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, company } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Campos obrigatórios" });
    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) return res.status(409).json({ error: "E-mail já cadastrado" });
    const hash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({ data: { name, email, password: hash } });
    const ws   = await prisma.workspace.create({
      data: { name: company || `${name}'s CRM`, ownerId: user.id }
    });
    await prisma.workspaceMember.create({
      data: { userId: user.id, workspaceId: ws.id, role: "ADMIN" }
    });
    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ token, user: { id: user.id, name, email }, workspace: ws });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Credenciais inválidas" });
    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: "7d" });
    const workspaces = await prisma.workspaceMember.findMany({
      where: { userId: user.id }, include: { workspace: true }
    });
    res.json({ token, user: { id: user.id, name: user.name, email }, workspaces });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// ── WORKSPACES ─────────────────────────────────────
app.get("/api/workspaces", auth, async (req, res) => {
  const members = await prisma.workspaceMember.findMany({
    where: { userId: req.user.id }, include: { workspace: true }
  });
  res.json(members.map(m => ({ ...m.workspace, role: m.role })));
});

// ── LEADS ──────────────────────────────────────────
app.get("/api/workspaces/:wsId/leads", auth, async (req, res) => {
  const { stage, search } = req.query;
  const where = {
    workspaceId: req.params.wsId,
    ...(stage  && { stage }),
    ...(search && { OR: [
      { name:    { contains: search, mode: "insensitive" } },
      { company: { contains: search, mode: "insensitive" } },
    ]}),
  };
  const leads = await prisma.lead.findMany({
    where, orderBy: { updatedAt: "desc" },
    include: { assignee: { select: { id: true, name: true } } }
  });
  res.json(leads);
});

app.post("/api/workspaces/:wsId/leads", auth, async (req, res) => {
  try {
    const { name, company, email, phone, value, source, notes } = req.body;
    const lead = await prisma.lead.create({
      data: { name, company, email, phone, value: Number(value) || 0,
        source, notes, workspaceId: req.params.wsId, stage: "Novo Lead", score: 50 }
    });
    res.status(201).json(lead);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar lead" });
  }
});

app.patch("/api/workspaces/:wsId/leads/:id", auth, async (req, res) => {
  const lead = await prisma.lead.update({ where: { id: req.params.id }, data: req.body });
  res.json(lead);
});

app.delete("/api/workspaces/:wsId/leads/:id", auth, async (req, res) => {
  await prisma.lead.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ── PIPELINE ───────────────────────────────────────
app.get("/api/workspaces/:wsId/pipeline", auth, async (req, res) => {
  const stages = ["Novo Lead","Qualificado","Proposta","Negociação","Fechado"];
  const pipeline = await Promise.all(stages.map(async stage => {
    const leads = await prisma.lead.findMany({
      where: { workspaceId: req.params.wsId, stage },
      orderBy: { score: "desc" },
      include: { assignee: { select: { name: true } } }
    });
    return { stage, leads, total: leads.reduce((a, l) => a + l.value, 0) };
  }));
  res.json(pipeline);
});

// ── TASKS ──────────────────────────────────────────
app.get("/api/workspaces/:wsId/tasks", auth, async (req, res) => {
  const tasks = await prisma.task.findMany({
    where: { lead: { workspaceId: req.params.wsId } },
    orderBy: { dueDate: "asc" },
    include: { lead: { select: { name: true, company: true } } }
  });
  res.json(tasks);
});

app.post("/api/workspaces/:wsId/tasks", auth, async (req, res) => {
  const { title, leadId, type, dueDate, priority } = req.body;
  const task = await prisma.task.create({
    data: { title, leadId, type, dueDate: dueDate ? new Date(dueDate) : null,
      priority: priority || "MEDIA" }
  });
  res.status(201).json(task);
});

app.patch("/api/workspaces/:wsId/tasks/:id", auth, async (req, res) => {
  const task = await prisma.task.update({ where: { id: req.params.id }, data: req.body });
  res.json(task);
});

// ── AUTOMAÇÕES ─────────────────────────────────────
app.get("/api/workspaces/:wsId/automations", auth, async (req, res) => {
  const autos = await prisma.automation.findMany({
    where: { workspaceId: req.params.wsId }, orderBy: { createdAt: "desc" }
  });
  res.json(autos);
});

app.post("/api/workspaces/:wsId/automations", auth, async (req, res) => {
  const { name, trigger, actions } = req.body;
  const auto = await prisma.automation.create({
    data: { name, trigger, actions, workspaceId: req.params.wsId, active: true }
  });
  res.status(201).json(auto);
});

app.patch("/api/workspaces/:wsId/automations/:id/toggle", auth, async (req, res) => {
  const current = await prisma.automation.findUnique({ where: { id: req.params.id } });
  const auto = await prisma.automation.update({
    where: { id: req.params.id }, data: { active: !current.active }
  });
  res.json(auto);
});

// ── RELATÓRIOS ─────────────────────────────────────
app.get("/api/workspaces/:wsId/reports/kpis", auth, async (req, res) => {
  const wid = req.params.wsId;
  const [total, closed, avgScore, overdue] = await Promise.all([
    prisma.lead.count({ where: { workspaceId: wid } }),
    prisma.lead.count({ where: { workspaceId: wid, stage: "Fechado" } }),
    prisma.lead.aggregate({ where: { workspaceId: wid }, _avg: { score: true } }),
    prisma.task.count({ where: { lead: { workspaceId: wid }, done: false, dueDate: { lt: new Date() } } }),
  ]);
  res.json({
    total, closed,
    conversionRate: total > 0 ? ((closed / total) * 100).toFixed(1) : 0,
    avgScore: Math.round(avgScore._avg.score || 0),
    overdueTasks: overdue,
  });
});

// ── WEBHOOK META ADS ───────────────────────────────
app.get("/api/webhooks/meta", (req, res) => {
  const { "hub.mode": mode, "hub.verify_token": token, "hub.challenge": challenge } = req.query;
  if (mode === "subscribe" && token === process.env.META_VERIFY_TOKEN)
    return res.send(challenge);
  res.sendStatus(403);
});

app.post("/api/webhooks/meta", async (req, res) => {
  res.sendStatus(200);
  console.log("Meta webhook recebido:", JSON.stringify(req.body));
});

// ── HEALTH ─────────────────────────────────────────
app.get("/health", (_req, res) =>
  res.json({ status: "ok", uptime: Math.round(process.uptime()) })
);

// ── START ──────────────────────────────────────────
app.listen(PORT, () => console.log(`CRM Pro API rodando na porta ${PORT}`));
