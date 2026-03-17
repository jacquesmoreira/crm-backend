// ─────────────────────────────────────────────────
// CRM Pro — Backend Node.js + Express
// Instalar: npm install express cors helmet bcrypt
//           jsonwebtoken prisma @prisma/client
//           express-rate-limit winston axios multer
// ─────────────────────────────────────────────────

import express         from "express";
import cors            from "cors";
import helmet          from "helmet";
import rateLimit       from "express-rate-limit";
import jwt             from "jsonwebtoken";
import bcrypt          from "bcrypt";
import winston         from "winston";
import { PrismaClient } from "@prisma/client";

const app    = express();
const prisma = new PrismaClient();
const PORT   = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_in_production";

// ─── LOGGER ──────────────────────────────────────
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/app.log" }),
  ],
});

// ─── MIDDLEWARE ───────────────────────────────────
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:3000", credentials: true }));
app.use(express.json({ limit: "10mb" }));

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.use("/api/", limiter);
app.use("/api/auth/", authLimiter);

// Request logging
app.use((req, _res, next) => {
  logger.info({ method: req.method, path: req.path, ip: req.ip });
  next();
});

// ─── JWT MIDDLEWARE ───────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token inválido ou expirado" });
  }
};

// Verificar acesso ao workspace
const wsAccess = async (req, res, next) => {
  const { workspaceId } = req.params;
  const member = await prisma.workspaceMember.findFirst({
    where: { userId: req.user.id, workspaceId },
  });
  if (!member) return res.status(403).json({ error: "Acesso negado ao workspace" });
  req.member = member;
  next();
};

// ════════════════════════════════════════════════
// ROTAS AUTH
// ════════════════════════════════════════════════
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, company } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Campos obrigatórios" });

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) return res.status(409).json({ error: "E-mail já cadastrado" });

    const hash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({ data: { name, email, password: hash } });

    // Criar workspace padrão
    const ws = await prisma.workspace.create({
      data: { name: company || `${name}'s CRM`, ownerId: user.id },
    });
    await prisma.workspaceMember.create({
      data: { userId: user.id, workspaceId: ws.id, role: "ADMIN" },
    });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    const refreshToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "30d" });

    res.status(201).json({ token, refreshToken, user: { id: user.id, name, email }, workspace: ws });
  } catch (err) {
    logger.error(err);
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
    const refreshToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "30d" });

    const workspaces = await prisma.workspaceMember.findMany({
      where: { userId: user.id },
      include: { workspace: true },
    });

    res.json({ token, refreshToken, user: { id: user.id, name: user.name, email }, workspaces });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: "Erro interno" });
  }
});

app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const payload = jwt.verify(refreshToken, JWT_SECRET);
    const token = jwt.sign({ id: payload.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch {
    res.status(401).json({ error: "Refresh token inválido" });
  }
});

// ════════════════════════════════════════════════
// ROTAS WORKSPACE
// ════════════════════════════════════════════════
app.get("/api/workspaces", auth, async (req, res) => {
  const members = await prisma.workspaceMember.findMany({
    where: { userId: req.user.id },
    include: { workspace: true },
  });
  res.json(members.map(m => ({ ...m.workspace, role: m.role })));
});

app.post("/api/workspaces", auth, async (req, res) => {
  const { name, plan = "STARTER" } = req.body;
  const ws = await prisma.workspace.create({
    data: { name, plan, ownerId: req.user.id },
  });
  await prisma.workspaceMember.create({
    data: { userId: req.user.id, workspaceId: ws.id, role: "ADMIN" },
  });
  res.status(201).json(ws);
});

app.post("/api/workspaces/:workspaceId/members", auth, wsAccess, async (req, res) => {
  const { email, role = "VENDEDOR" } = req.body;
  if (req.member.role !== "ADMIN") return res.status(403).json({ error: "Apenas admins podem convidar" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

  await prisma.workspaceMember.upsert({
    where: { userId_workspaceId: { userId: user.id, workspaceId: req.params.workspaceId } },
    update: { role },
    create: { userId: user.id, workspaceId: req.params.workspaceId, role },
  });
  res.json({ success: true });
});

// ════════════════════════════════════════════════
// ROTAS LEADS
// ════════════════════════════════════════════════
app.get("/api/workspaces/:workspaceId/leads", auth, wsAccess, async (req, res) => {
  const { stage, search, assignee, page = 1, limit = 50 } = req.query;
  const where = {
    workspaceId: req.params.workspaceId,
    ...(stage   && { stage }),
    ...(assignee && { assigneeId: assignee }),
    ...(search  && { OR: [
      { name:    { contains: search, mode: "insensitive" } },
      { company: { contains: search, mode: "insensitive" } },
      { email:   { contains: search, mode: "insensitive" } },
    ]}),
  };

  const [leads, total] = await Promise.all([
    prisma.lead.findMany({
      where, orderBy: { updatedAt: "desc" },
      skip: (page - 1) * limit, take: Number(limit),
      include: { assignee: { select: { id: true, name: true } }, tags: true },
    }),
    prisma.lead.count({ where }),
  ]);
  res.json({ leads, total, page: Number(page), pages: Math.ceil(total / limit) });
});

app.post("/api/workspaces/:workspaceId/leads", auth, wsAccess, async (req, res) => {
  try {
    const { name, company, email, phone, value, source, assigneeId, notes, tags = [] } = req.body;
    const lead = await prisma.lead.create({
      data: {
        name, company, email, phone, value: Number(value),
        source, assigneeId, notes, workspaceId: req.params.workspaceId,
        stage: "Novo Lead", score: 50,
        tags: { connectOrCreate: tags.map(t => ({ where: { name_workspaceId: { name: t, workspaceId: req.params.workspaceId } }, create: { name: t, workspaceId: req.params.workspaceId } })) },
      },
      include: { assignee: { select: { id: true, name: true } }, tags: true },
    });

    // Registrar na timeline
    await prisma.activity.create({
      data: { leadId: lead.id, userId: req.user.id, type: "CRIADO", description: `Lead criado via ${source}` },
    });

    res.status(201).json(lead);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: "Erro ao criar lead" });
  }
});

app.patch("/api/workspaces/:workspaceId/leads/:id", auth, wsAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const prev = await prisma.lead.findFirst({ where: { id, workspaceId: req.params.workspaceId } });
    if (!prev) return res.status(404).json({ error: "Lead não encontrado" });

    const lead = await prisma.lead.update({ where: { id }, data: req.body });

    // Log mudança de estágio
    if (req.body.stage && req.body.stage !== prev.stage) {
      await prisma.activity.create({
        data: { leadId: id, userId: req.user.id, type: "ESTAGIO", description: `${prev.stage} → ${req.body.stage}` },
      });
      // Trigger automações
      triggerAutomations(req.params.workspaceId, "STAGE_CHANGE", { lead, prevStage: prev.stage, newStage: req.body.stage });
    }

    res.json(lead);
  } catch (err) {
    res.status(500).json({ error: "Erro ao atualizar lead" });
  }
});

app.patch("/api/workspaces/:workspaceId/leads/:id/stage", auth, wsAccess, async (req, res) => {
  const { id } = req.params;
  const { stage } = req.body;
  if (!Object.keys({ "Novo Lead":1, "Qualificado":1, "Proposta":1, "Negociação":1, "Fechado":1 }).includes(stage))
    return res.status(400).json({ error: "Estágio inválido" });

  const lead = await prisma.lead.update({ where: { id }, data: { stage } });
  res.json(lead);
});

app.delete("/api/workspaces/:workspaceId/leads/:id", auth, wsAccess, async (req, res) => {
  if (req.member.role === "VENDEDOR") return res.status(403).json({ error: "Sem permissão para excluir" });
  await prisma.lead.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// Timeline
app.get("/api/workspaces/:workspaceId/leads/:id/activities", auth, wsAccess, async (req, res) => {
  const activities = await prisma.activity.findMany({
    where: { leadId: req.params.id },
    orderBy: { createdAt: "desc" },
    include: { user: { select: { name: true } } },
  });
  res.json(activities);
});

// ════════════════════════════════════════════════
// ROTAS PIPELINE
// ════════════════════════════════════════════════
app.get("/api/workspaces/:workspaceId/pipeline", auth, wsAccess, async (req, res) => {
  const stages = ["Novo Lead", "Qualificado", "Proposta", "Negociação", "Fechado"];
  const pipeline = await Promise.all(stages.map(async stage => {
    const leads = await prisma.lead.findMany({
      where: { workspaceId: req.params.workspaceId, stage },
      orderBy: { score: "desc" },
      include: { assignee: { select: { name: true } }, tags: true },
    });
    return {
      stage,
      leads,
      total: leads.reduce((a, l) => a + l.value, 0),
    };
  }));
  res.json(pipeline);
});

// ════════════════════════════════════════════════
// ROTAS TASKS
// ════════════════════════════════════════════════
app.get("/api/workspaces/:workspaceId/tasks", auth, wsAccess, async (req, res) => {
  const { leadId, done, assigneeId } = req.query;
  const tasks = await prisma.task.findMany({
    where: {
      lead: { workspaceId: req.params.workspaceId },
      ...(leadId     && { leadId }),
      ...(assigneeId && { assigneeId }),
      ...(done !== undefined && { done: done === "true" }),
    },
    orderBy: [{ dueDate: "asc" }, { priority: "desc" }],
    include: { lead: { select: { name: true, company: true } }, assignee: { select: { name: true } } },
  });
  res.json(tasks);
});

app.post("/api/workspaces/:workspaceId/tasks", auth, wsAccess, async (req, res) => {
  const { title, leadId, type, dueDate, priority = "MEDIA", assigneeId } = req.body;
  const task = await prisma.task.create({
    data: { title, leadId, type, dueDate: new Date(dueDate), priority, assigneeId: assigneeId || req.user.id },
  });
  res.status(201).json(task);
});

app.patch("/api/workspaces/:workspaceId/tasks/:id", auth, wsAccess, async (req, res) => {
  const task = await prisma.task.update({ where: { id: req.params.id }, data: req.body });
  res.json(task);
});

// ════════════════════════════════════════════════
// ROTAS AUTOMAÇÕES
// ════════════════════════════════════════════════
app.get("/api/workspaces/:workspaceId/automations", auth, wsAccess, async (req, res) => {
  const autos = await prisma.automation.findMany({
    where: { workspaceId: req.params.workspaceId },
    orderBy: { createdAt: "desc" },
  });
  res.json(autos);
});

app.post("/api/workspaces/:workspaceId/automations", auth, wsAccess, async (req, res) => {
  const { name, trigger, actions } = req.body;
  const auto = await prisma.automation.create({
    data: { name, trigger, actions, workspaceId: req.params.workspaceId, active: true },
  });
  res.status(201).json(auto);
});

app.patch("/api/workspaces/:workspaceId/automations/:id/toggle", auth, wsAccess, async (req, res) => {
  const current = await prisma.automation.findUnique({ where: { id: req.params.id } });
  const auto = await prisma.automation.update({
    where: { id: req.params.id },
    data: { active: !current.active },
  });
  res.json(auto);
});

// Motor de automações
async function triggerAutomations(workspaceId, event, context) {
  try {
    const autos = await prisma.automation.findMany({ where: { workspaceId, active: true } });
    for (const auto of autos) {
      const t = auto.trigger;
      let match = false;

      if (event === "LEAD_CREATED" && t.type === "novo_lead") {
        match = !t.source || t.source === context.lead.source;
      } else if (event === "STAGE_CHANGE" && t.type === "sem_avanco") {
        match = t.stage === context.newStage;
      }

      if (match) {
        await executeActions(auto.actions, context, workspaceId);
        await prisma.automationLog.create({
          data: { automationId: auto.id, leadId: context.lead.id, event, status: "EXECUTADO" },
        });
      }
    }
  } catch (err) {
    logger.error("Automation error:", err);
  }
}

async function executeActions(actions, context, workspaceId) {
  for (const action of actions) {
    if (action.type === "criar_tarefa") {
      await prisma.task.create({
        data: { title: action.label, leadId: context.lead.id, type: "Follow-up",
          dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000), priority: "ALTA" },
      });
    } else if (action.type === "tag") {
      await prisma.lead.update({ where: { id: context.lead.id }, data: { tags: {
        connectOrCreate: [{ where: { name_workspaceId: { name: action.label, workspaceId } }, create: { name: action.label, workspaceId } }],
      }}});
    }
  }
}

// ════════════════════════════════════════════════
// ROTAS META ADS WEBHOOK
// ════════════════════════════════════════════════
app.get("/api/webhooks/meta", (req, res) => {
  const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN;
  const { "hub.mode": mode, "hub.verify_token": token, "hub.challenge": challenge } = req.query;
  if (mode === "subscribe" && token === VERIFY_TOKEN) return res.send(challenge);
  res.sendStatus(403);
});

app.post("/api/webhooks/meta", async (req, res) => {
  res.sendStatus(200); // Responder imediatamente
  const entries = req.body?.entry || [];

  for (const entry of entries) {
    for (const change of entry.changes || []) {
      if (change.field === "leadgen") {
        const { leadgen_id, page_id, form_id, ad_id } = change.value;
        const config = await prisma.metaAdsConfig.findFirst({
          where: { pageId: String(page_id) },
          include: { workspace: true },
        });
        if (!config) continue;

        // Criar lead no CRM
        try {
          const lead = await prisma.lead.create({
            data: {
              name: "Lead Meta Ads",
              source: "Meta Ads",
              stage: "Novo Lead",
              score: 50,
              workspaceId: config.workspaceId,
              externalId: String(leadgen_id),
              metadata: { ad_id, form_id, page_id },
            },
          });
          triggerAutomations(config.workspaceId, "LEAD_CREATED", { lead });
          logger.info(`Meta lead synced: ${leadgen_id}`);
        } catch (err) {
          logger.error("Meta lead sync error:", err);
        }
      }
    }
  }
});

// ════════════════════════════════════════════════
// ROTAS RELATÓRIOS
// ════════════════════════════════════════════════
app.get("/api/workspaces/:workspaceId/reports/funnel", auth, wsAccess, async (req, res) => {
  const stages = ["Novo Lead", "Qualificado", "Proposta", "Negociação", "Fechado"];
  const data = await Promise.all(stages.map(async stage => ({
    stage,
    count: await prisma.lead.count({ where: { workspaceId: req.params.workspaceId, stage } }),
    value: (await prisma.lead.aggregate({
      where: { workspaceId: req.params.workspaceId, stage },
      _sum: { value: true },
    }))._sum.value || 0,
  })));
  res.json(data);
});

app.get("/api/workspaces/:workspaceId/reports/revenue", auth, wsAccess, async (req, res) => {
  const { months = 6 } = req.query;
  const data = [];
  for (let i = months - 1; i >= 0; i--) {
    const date = new Date();
    date.setMonth(date.getMonth() - i);
    const start = new Date(date.getFullYear(), date.getMonth(), 1);
    const end   = new Date(date.getFullYear(), date.getMonth() + 1, 0);
    const result = await prisma.lead.aggregate({
      where: { workspaceId: req.params.workspaceId, stage: "Fechado", closedAt: { gte: start, lte: end } },
      _sum: { value: true },
    });
    data.push({ month: start.toLocaleDateString("pt-BR", { month: "short" }), revenue: result._sum.value || 0 });
  }
  res.json(data);
});

app.get("/api/workspaces/:workspaceId/reports/kpis", auth, wsAccess, async (req, res) => {
  const wid = req.params.workspaceId;
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

// ─── HEALTH ───────────────────────────────────────
app.get("/health", (_req, res) => res.json({ status: "ok", uptime: process.uptime() }));

// ─── ERROR HANDLER ────────────────────────────────
app.use((err, _req, res, _next) => {
  logger.error(err.stack);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// ─── START ────────────────────────────────────────
app.listen(PORT, () => logger.info(`CRM Pro API rodando na porta ${PORT}`));

export default app;
