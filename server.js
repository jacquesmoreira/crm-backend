const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const jwt          = require("jsonwebtoken");
const bcrypt       = require("bcrypt");
const { PrismaClient } = require("@prisma/client");
require("dotenv").config();

const app = express();
const http = require("http");
const { Server } = require("socket.io");
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
global.io = io;

io.on("connection", (socket) => {
  socket.on("join", (wsId) => {
    socket.join(wsId);
    console.log(`Socket joined workspace: ${wsId}`);
  });
});
app.set("trust proxy", 1);
const prisma = new PrismaClient();
const PORT   = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "crm_secret_2026";

app.use(helmet());
app.use(cors({ origin: "*" }));
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

    // Verificar limite de leads por plano
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const plan = (ws?.plan || "FREE").toUpperCase();
    const LIMITS = { FREE: 5, STARTER: 500, PRO: Infinity, ENTERPRISE: Infinity };
    const limit = LIMITS[plan] ?? 5;
    if(limit !== Infinity){
      const count = await prisma.lead.count({ where: { workspaceId: req.params.wsId } });
      if(count >= limit){
        return res.status(403).json({ error: `Limite de ${limit} leads atingido no plano ${plan}. Faça upgrade para continuar.` });
      }
    }

    const lead = await prisma.lead.create({
      data: { name, company, email, phone, value: Number(value) || 0,
        source, notes, workspaceId: req.params.wsId, stage: "Novo Lead", score: 50 }
    });
    await prisma.activity.create({
      data:{ leadId:lead.id, userId:req.user.id, type:"CRIADO", description:`Lead ${name} criado` }
    }).catch(()=>{});
    res.status(201).json(lead);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar lead" });
  }
});

app.patch("/api/workspaces/:wsId/leads/:id", auth, async (req, res) => {
  try {
    const lead = await prisma.lead.update({ where: { id: req.params.id }, data: req.body });
    if(req.body.stage){
      await prisma.activity.create({
        data:{ leadId:req.params.id, userId:req.user.id, type:"ESTAGIO", description:`Etapa alterada para ${req.body.stage}` }
      }).catch(()=>{});
    } else {
      await prisma.activity.create({
        data:{ leadId:req.params.id, userId:req.user.id, type:"NOTA", description:"Lead atualizado" }
      }).catch(()=>{});
    }
    res.json(lead);
  } catch (err) {
    res.status(500).json({ error: "Erro ao atualizar lead" });
  }
});

app.delete("/api/workspaces/:wsId/leads/:id", auth, async (req, res) => {
  await prisma.lead.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ── ACTIVITIES (Timeline) ──────────────────────────
app.get("/api/workspaces/:wsId/leads/:id/activities", auth, async (req, res) => {
  try {
    const activities = await prisma.activity.findMany({
      where: { leadId: req.params.id },
      orderBy: { createdAt: "desc" },
      include: { user: { select: { name: true } } }
    });
    res.json(activities);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar atividades" });
  }
});

app.post("/api/workspaces/:wsId/leads/:id/activities", auth, async (req, res) => {
  try {
    const { type, description, metadata } = req.body;
    const activity = await prisma.activity.create({
      data: { leadId: req.params.id, userId: req.user.id, type, description, metadata }
    });
    res.status(201).json(activity);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar atividade" });
  }
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

// Leads por dia (últimos 30 dias)
app.get("/api/workspaces/:wsId/reports/leads-by-day", auth, async (req, res) => {
  try {
    const wid = req.params.wsId;
    const days = parseInt(req.query.days) || 30;
    const since = new Date();
    since.setDate(since.getDate() - days);
    const leads = await prisma.lead.findMany({
      where: { workspaceId: wid, createdAt: { gte: since } },
      select: { createdAt: true },
    });
    // Agrupar por dia
    const counts = {};
    for(let i = days-1; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0,10);
      counts[key] = 0;
    }
    leads.forEach(l => {
      const key = l.createdAt.toISOString().slice(0,10);
      if(counts[key] !== undefined) counts[key]++;
    });
    const data = Object.entries(counts).map(([day, count]) => ({
      day: day.slice(5), // MM-DD
      count,
    }));
    res.json(data);
  } catch(err) {
    res.status(500).json({ error: "Erro ao buscar leads por dia" });
  }
});

// Leads em risco (sem atividade há mais de 5 dias)
app.get("/api/workspaces/:wsId/reports/at-risk", auth, async (req, res) => {
  try {
    const wid = req.params.wsId;
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 5);
    const leads = await prisma.lead.findMany({
      where: {
        workspaceId: wid,
        stage: { not: "Fechado" },
        updatedAt: { lt: cutoff },
      },
      orderBy: { updatedAt: "asc" },
      take: 10,
    });
    const data = leads.map(l => ({
      ...l,
      daysSince: Math.floor((Date.now() - new Date(l.updatedAt).getTime()) / (1000*60*60*24)),
    }));
    res.json(data);
  } catch(err) {
    res.status(500).json({ error: "Erro ao buscar leads em risco" });
  }
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

// ── WHATSAPP (Evolution API) ───────────────────────────
const EVO_URL = process.env.EVOLUTION_API_URL || "https://evolution-api-production-a08d.up.railway.app";
const EVO_KEY = process.env.EVOLUTION_API_KEY || "leadturbo_evo_key_2026";

const evoHeaders = {
  "Content-Type": "application/json",
  "apikey": EVO_KEY,
  "Apikey": EVO_KEY
};

const getInstance = (wsId) => `leadturbo_${wsId}`;

// Criar/conectar instância
app.post("/api/workspaces/:wsId/whatsapp/connect", auth, async (req, res) => {
  try {
    const instanceName = getInstance(req.params.wsId);
    // Tenta criar — se já existe ignora o erro
    await fetch(`${EVO_URL}/instance/create`, {
      method: "POST",
      headers: evoHeaders,
      body: JSON.stringify({ instanceName, qrcode: true, integration: "WHATSAPP-BAILEYS" })
    }).catch(()=>{});
    // Retorna QR Code
    const r = await fetch(`${EVO_URL}/instance/connect/${instanceName}`, { headers: evoHeaders });
    const d = await r.json();
    res.json(d);
  } catch (err) {
    res.status(500).json({ error: "Erro ao conectar WhatsApp" });
  }
});

// QR Code
app.get("/api/workspaces/:wsId/whatsapp/qrcode", auth, async (req, res) => {
  try {
    const instanceName = getInstance(req.params.wsId);
    const r = await fetch(`${EVO_URL}/instance/connect/${instanceName}`, { headers: evoHeaders });
    const d = await r.json();
    res.json(d);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar QR Code" });
  }
});

// Status
app.get("/api/workspaces/:wsId/whatsapp/status", auth, async (req, res) => {
  try {
    const instanceName = getInstance(req.params.wsId);
    const r = await fetch(`${EVO_URL}/instance/fetchInstances?instanceName=${instanceName}`, { headers: evoHeaders });
    const d = await r.json();
    const instance = Array.isArray(d) ? d[0] : d;
    res.json({ connected: instance?.connectionStatus === "open", status: instance?.connectionStatus || "close" });
  } catch (err) {
    res.status(500).json({ error: "Erro ao verificar status" });
  }
});

// Enviar mensagem
app.post("/api/workspaces/:wsId/whatsapp/send", auth, async (req, res) => {
  try {
    const { phone, message } = req.body;
    const instanceName = getInstance(req.params.wsId);
    const evoKey = process.env.EVOLUTION_API_KEY || "leadturbo_evo_key_2026";
    const evoUrl = process.env.EVOLUTION_API_URL || "https://evolution-api-production-a08d.up.railway.app";
    const r = await fetch(`${evoUrl}/message/sendText/${instanceName}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "apikey": evoKey },
      body: JSON.stringify({ number: phone.replace(/\D/g, ""), text: message })
    });
    const d = await r.json();
    res.json(d);
  } catch (err) {
    res.status(500).json({ error: "Erro ao enviar mensagem" });
  }
});

// Webhook receber mensagens
app.post("/api/webhooks/whatsapp", async (req, res) => {
  res.sendStatus(200);
  const { event, instance, data } = req.body;
  if (event === "messages.upsert" && data?.message) {
    const phone = data.key?.remoteJid?.replace("@s.whatsapp.net", "");
    const text = data.message?.conversation || data.message?.extendedTextMessage?.text || "";
    const from = data.key?.fromMe ? "me" : "lead";
    const wsId = instance?.replace("leadturbo_", "");
    console.log(`WA [${wsId}] ${from} ${phone}: ${text}`);
    // Emitir via WebSocket para o frontend (próxima etapa)
    console.log("global.io exists:", !!global.io, "wsId:", wsId);
if (global.io) {
  global.io.to(wsId).emit("wa_message", { phone, text, from, time: new Date() });
  console.log("Emitted wa_message to:", wsId);
}
  }
});

// ── AI PROXY ──────────────────────────────────────────
app.post("/api/ai/analyze", auth, async (req, res) => {
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify(req.body)
    });
    const d = await r.json();
    res.json(d);
  } catch (err) {
    res.status(500).json({ error: "Erro ao chamar IA" });
  }
});

// ── ACTIVITIES (Timeline) ──────────────────────────
app.get("/api/workspaces/:wsId/leads/:id/activities", auth, async (req, res) => {
  try {
    const activities = await prisma.activity.findMany({
      where: { leadId: req.params.id },
      orderBy: { createdAt: "desc" },
      include: { user: { select: { name: true } } }
    });
    res.json(activities);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar atividades" });
  }
});

app.post("/api/workspaces/:wsId/leads/:id/activities", auth, async (req, res) => {
  try {
    const { type, description, metadata } = req.body;
    const activity = await prisma.activity.create({
      data: { leadId: req.params.id, userId: req.user.id, type, description, metadata }
    });
    res.status(201).json(activity);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar atividade" });
  }
});

// ── CAMPOS PERSONALIZADOS ──────────────────────────
app.get("/api/workspaces/:wsId/custom-fields", auth, async (req, res) => {
  try {
    const fields = await prisma.customField.findMany({
      where: { workspaceId: req.params.wsId },
      orderBy: { order: "asc" }
    });
    res.json(fields);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar campos" });
  }
});

app.post("/api/workspaces/:wsId/custom-fields", auth, async (req, res) => {
  try {
    const { name, type, options, required } = req.body;
    const count = await prisma.customField.count({ where: { workspaceId: req.params.wsId } });
    const field = await prisma.customField.create({
      data: { name, type: type||"text", options, required: required||false, order: count, workspaceId: req.params.wsId }
    });
    res.status(201).json(field);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar campo" });
  }
});

app.delete("/api/workspaces/:wsId/custom-fields/:id", auth, async (req, res) => {
  try {
    await prisma.customField.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao deletar campo" });
  }
});

// ── PIPELINES ──────────────────────────────────────
app.get("/api/workspaces/:wsId/pipelines", auth, async (req, res) => {
  try {
    const pipelines = await prisma.pipeline.findMany({
      where: { workspaceId: req.params.wsId },
      orderBy: { createdAt: "asc" }
    });
    res.json(pipelines);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar pipelines" });
  }
});

app.post("/api/workspaces/:wsId/pipelines", auth, async (req, res) => {
  try {
    const { name, stages } = req.body;
    const pipeline = await prisma.pipeline.create({
      data: { name, stages: stages||["Novo Lead","Qualificado","Proposta","Negociação","Fechado"], workspaceId: req.params.wsId }
    });
    res.status(201).json(pipeline);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar pipeline" });
  }
});

app.patch("/api/workspaces/:wsId/pipelines/:id", auth, async (req, res) => {
  try {
    const pipeline = await prisma.pipeline.update({
      where: { id: req.params.id }, data: req.body
    });
    res.json(pipeline);
  } catch (err) {
    res.status(500).json({ error: "Erro ao atualizar pipeline" });
  }
});

app.delete("/api/workspaces/:wsId/pipelines/:id", auth, async (req, res) => {
  try {
    await prisma.pipeline.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao deletar pipeline" });
  }
});

// ── E-MAIL (SMTP) ──────────────────────────────────
const nodemailer = require("nodemailer");

app.post("/api/workspaces/:wsId/email/config", auth, async (req, res) => {
  try {
    const { host, port, user, pass, fromName } = req.body;
    await prisma.workspace.update({
      where: { id: req.params.wsId },
      data: { metadata: { smtpHost: host, smtpPort: Number(port)||465, smtpUser: user, smtpPass: pass, smtpFromName: fromName||user } }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao salvar configuração" });
  }
});

app.get("/api/workspaces/:wsId/email/config", auth, async (req, res) => {
  try {
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    res.json({ host: meta.smtpHost||"", port: meta.smtpPort||465, user: meta.smtpUser||"", fromName: meta.smtpFromName||"" });
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar configuração" });
  }
});

app.post("/api/workspaces/:wsId/email/send", auth, async (req, res) => {
  try {
    const { to, subject, body, leadId } = req.body;
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    if(!meta.smtpHost||!meta.smtpUser||!meta.smtpPass) return res.status(400).json({ error: "SMTP não configurado" });
    const transporter = nodemailer.createTransport({
      host: meta.smtpHost, port: meta.smtpPort||465, secure: (meta.smtpPort||465)===465,
      auth: { user: meta.smtpUser, pass: meta.smtpPass }
    });
    await transporter.sendMail({ from: `"${meta.smtpFromName||meta.smtpUser}" <${meta.smtpUser}>`, to, subject, text: body, html: body.replace(/\n/g,"<br>") });
    if(leadId){
      await prisma.activity.create({
        data:{ leadId, userId:req.user.id, type:"EMAIL", description:`E-mail enviado para ${to}: ${subject}` }
      }).catch(()=>{});
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao enviar e-mail: "+err.message });
  }
});

// ── STRIPE / COBRANÇA ─────────────────────────────
const Stripe = require("stripe");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const PLANS = {
  starter: { priceId: "price_1TIqkH3DNcWhpXE15eqSq2oQ", name: "Starter", amount: 7700 },
  pro:     { priceId: "price_1TIqkk3DNcWhpXE1xc0pZbyF", name: "Pro",     amount: 14700 },
  agency:  { priceId: "price_1TIql93DNcWhpXE14WJRCnnH", name: "Agency",  amount: 29700 },
};

// Criar sessão de checkout
app.post("/api/billing/checkout", auth, async (req, res) => {
  try {
    const { plan } = req.body;
    const p = PLANS[plan];
    if(!p) return res.status(400).json({ error: "Plano inválido" });
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    
    const trialEligible = !user.trialUsed;
    
    const sessionParams = {
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: user.email,
      line_items: [{ price: p.priceId, quantity: 1 }],
      success_url: `${process.env.FRONTEND_URL || "https://leadturbo.shop"}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL || "https://leadturbo.shop"}/pricing`,
      metadata: { userId: req.user.id, plan },
    };

    if(trialEligible){
      sessionParams.trial_period_days = 15;
      sessionParams.payment_method_collection = "if_required";
    }

    const session = await stripe.checkout.sessions.create(sessionParams);

    if(trialEligible){
      await prisma.user.update({
        where: { id: req.user.id },
        data: { trialUsed: true, trialStarted: new Date() }
      });
    }

    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar checkout" });
  }
});

// Status da assinatura
app.get("/api/billing/subscription", auth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if(!user.stripeCustomerId) return res.json({ plan: "free", status: "none" });
    const subs = await stripe.subscriptions.list({ customer: user.stripeCustomerId, limit: 1 });
    if(!subs.data.length) return res.json({ plan: "free", status: "none" });
    const sub = subs.data[0];
    const priceId = sub.items.data[0].price.id;
    const plan = Object.entries(PLANS).find(([,v])=>v.priceId===priceId)?.[0]||"free";
    res.json({ plan, status: sub.status, renewsAt: new Date(sub.current_period_end*1000) });
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar assinatura" });
  }
});

// Portal do cliente (gerenciar assinatura)
app.post("/api/billing/portal", auth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if(!user.stripeCustomerId) return res.status(400).json({ error: "Sem assinatura ativa" });
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.FRONTEND_URL || "https://leadturbo.shop"}`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: "Erro ao abrir portal" });
  }
});

// Webhook Stripe
app.post("/api/webhooks/stripe", express.raw({type:"application/json"}), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET||"");
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if(event.type === "checkout.session.completed") {
    const session = event.data.object;
    const { userId, plan } = session.metadata;
    await prisma.user.update({
      where: { id: userId },
      data: { stripeCustomerId: session.customer }
    }).catch(()=>{});
    const ws = await prisma.workspaceMember.findFirst({ where: { userId } });
    if(ws) await prisma.workspace.update({
      where: { id: ws.workspaceId },
      data: { plan: plan.toUpperCase() === "AGENCY" ? "ENTERPRISE" : plan.toUpperCase() === "PRO" ? "PRO" : "STARTER" }
    }).catch(()=>{});
  }
  res.json({ received: true });
});

// ── META ADS OAUTH ─────────────────────────────────
const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;
const META_REDIRECT = `${process.env.FRONTEND_URL || "https://leadturbo.shop"}/api/meta/oauth/callback`;

// Iniciar OAuth - redireciona para o Meta
app.get("/api/meta/oauth/start", async (req, res) => {
  const { wsId, token } = req.query;
  let userId;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    userId = decoded.id;
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
  const state = Buffer.from(JSON.stringify({ userId, wsId })).toString("base64");
  const url = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${META_APP_ID}&redirect_uri=${encodeURIComponent(`https://crm-backend-production-987f.up.railway.app/api/meta/oauth/callback`)}&scope=ads_read,ads_management,business_management&state=${state}`;
  res.redirect(url);
});

// Callback OAuth - recebe o code e troca pelo token
app.get("/api/meta/oauth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId, wsId } = JSON.parse(Buffer.from(state, "base64").toString());
    // Troca code por token
    const r = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${META_APP_ID}&client_secret=${META_APP_SECRET}&redirect_uri=${encodeURIComponent(`https://crm-backend-production-987f.up.railway.app/api/meta/oauth/callback`)}&code=${code}`);
    const d = await r.json();
    if(!d.access_token) throw new Error("Token não recebido");
    // Busca contas de anúncio do usuário
    const adR = await fetch(`https://graph.facebook.com/v19.0/me/adaccounts?fields=id,name,account_status,currency&limit=50&access_token=${d.access_token}`);
    const adD = await adR.json();
    // Salva token e ad accounts no workspace
    const ws = await prisma.workspace.findUnique({ where: { id: wsId } });
    const meta = ws?.metadata || {};
    await prisma.workspace.update({
      where: { id: wsId },
      data: { metadata: { ...meta, metaAccessToken: d.access_token, metaAdAccounts: adD.data || [], metaConnectedAt: new Date() } }
    });
    res.redirect(`${process.env.FRONTEND_URL || "https://leadturbo.shop"}/?meta=connected`);
  } catch (err) {
    console.error("Meta OAuth error:", err);
    res.redirect(`${process.env.FRONTEND_URL || "https://leadturbo.shop"}/?meta=error`);
  }
});

// Buscar campanhas do workspace
app.get("/api/workspaces/:wsId/meta/campaigns", auth, async (req, res) => {
  try {
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    if(!meta.metaAccessToken) return res.status(400).json({ error: "Meta Ads não conectado" });
    const accountId = req.query.accountId || meta.metaAdAccounts?.[0]?.id;
    if(!accountId) return res.status(400).json({ error: "Nenhuma conta de anúncios encontrada" });
    // Busca campanhas com métricas
    const { datePreset, dateStart, dateEnd } = req.query;
    const dateParam = dateStart && dateEnd
     ? `time_range({"since":"${dateStart}","until":"${dateEnd}"})`
     : `date_preset(${datePreset||"last_30d"})`;
    const r = await fetch(`https://graph.facebook.com/v19.0/${accountId}/campaigns?fields=id,name,status,objective,daily_budget,lifetime_budget,insights.${dateParam}{spend,impressions,clicks,reach,frequency,cpm,cpc,ctr,actions,action_values,cost_per_action_type,website_purchase_roas,conversions}&limit=50&access_token=${meta.metaAccessToken}`);
    const d = await r.json();
    if(d.error) return res.status(400).json({ error: d.error.message });
    res.json(d.data || []);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar campanhas" });
  }
});

// Status da conexão Meta
app.get("/api/workspaces/:wsId/meta/status", auth, async (req, res) => {
  try {
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    res.json({
      connected: !!meta.metaAccessToken,
      adAccounts: meta.metaAdAccounts || [],
      connectedAt: meta.metaConnectedAt || null
    });
  } catch (err) {
    res.status(500).json({ error: "Erro ao verificar status" });
  }
});

// Desconectar Meta
app.delete("/api/workspaces/:wsId/meta/disconnect", auth, async (req, res) => {
  try {
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    delete meta.metaAccessToken;
    delete meta.metaAdAccounts;
    delete meta.metaConnectedAt;
    await prisma.workspace.update({ where: { id: req.params.wsId }, data: { metadata: meta } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao desconectar" });
  }
});

// Conjuntos de anúncios (Ad Sets)
app.get("/api/workspaces/:wsId/meta/adsets", auth, async (req, res) => {
  try {
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    if(!meta.metaAccessToken) return res.status(400).json({ error: "Meta Ads não conectado" });
    const { campaignId, datePreset, dateStart, dateEnd } = req.query;
    const dateParam = dateStart && dateEnd
      ? `time_range({"since":"${dateStart}","until":"${dateEnd}"})`
      : `date_preset(${datePreset||"last_30d"})`;
    const r = await fetch(`https://graph.facebook.com/v19.0/${campaignId}/adsets?fields=id,name,status,daily_budget,lifetime_budget,insights.${dateParam}{spend,impressions,clicks,reach,frequency,cpm,cpc,ctr,actions,action_values,cost_per_action_type,website_purchase_roas}&limit=50&access_token=${meta.metaAccessToken}`);
    const d = await r.json();
    if(d.error) return res.status(400).json({ error: d.error.message });
    res.json(d.data || []);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar conjuntos" });
  }
});

// Anúncios (Ads)
app.get("/api/workspaces/:wsId/meta/ads", auth, async (req, res) => {
  try {
    const ws = await prisma.workspace.findUnique({ where: { id: req.params.wsId } });
    const meta = ws?.metadata || {};
    if(!meta.metaAccessToken) return res.status(400).json({ error: "Meta Ads não conectado" });
    const { adsetId, datePreset, dateStart, dateEnd } = req.query;
    const dateParam = dateStart && dateEnd
     ? `time_range({"since":"${dateStart}","until":"${dateEnd}"})`
     : `date_preset(${datePreset||"last_30d"})`;
    const r = await fetch(`https://graph.facebook.com/v19.0/${adsetId}/ads?fields=id,name,status,creative{id,name,thumbnail_url},insights.${dateParam}{spend,impressions,clicks,reach,cpm,cpc,ctr,actions,action_values,cost_per_action_type,website_purchase_roas}&limit=50&access_token=${meta.metaAccessToken}`);
    const d = await r.json();
    if(d.error) return res.status(400).json({ error: d.error.message });
    res.json(d.data || []);
  } catch (err) {
    res.status(500).json({ error: "Erro ao buscar anúncios" });
  }
});

// ── HEALTH ─────────────────────────────────────────
app.get("/health", (_req, res) =>
  res.json({ status: "ok", uptime: Math.round(process.uptime()) })
);

// ── START ──────────────────────────────────────────
server.listen(PORT, "0.0.0.0", () => console.log(`CRM Pro API rodando na porta ${PORT}`));