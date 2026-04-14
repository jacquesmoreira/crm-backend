// ── wa-autoresponder.js ─────────────────────────────────────────────
// Módulo de autoresponder WhatsApp para ClienData
// Plugar no webhook existente: /api/webhooks/whatsapp
//
// USO:
// 1. Copie este arquivo para a pasta do crm-backend
// 2. No server.js, importe: const { handleAutoReply } = require("./wa-autoresponder");
// 3. No webhook handler, chame: await handleAutoReply(instanceName, phone, text);
// 4. Adicione AUTORESPONDER_ENABLED=true nas variáveis de ambiente
// ────────────────────────────────────────────────────────────────────

const EVO_URL = process.env.EVOLUTION_API_URL;
const EVO_KEY = process.env.EVOLUTION_API_KEY;

// ── MENSAGENS DO FLUXO ─────────────────────────────────────────────

const MESSAGES = {
  welcome: `Oi! Que bom que você me mandou mensagem! 😊

Aqui é o Dr. Augusto Villa, fisioterapeuta há 14 anos.

Me conta: qual é a principal dificuldade que você sente no joelho hoje?

Pode ser subir escada, caminhar, levantar da cadeira, dor ao agachar... Me fala que eu te oriento.`,

  protocol: `Entendi! Isso é muito mais comum do que parece — e na maioria dos casos dá pra melhorar bastante com os exercícios certos.

Eu criei o *Protocolo Joelho 100%* justamente pra isso.

São *4 fases progressivas*:
✅ Fase 1 → Mobilidade leve (respeita seu nível)
✅ Fase 2 → Ativação e controle
✅ Fase 3 → Força e resistência
✅ Fase 4 → Funcionalidade do dia a dia

Cada sessão dura *10 minutos*. Tudo com vídeo, sem equipamento, feito em casa.

O investimento é *R$67* (pagamento único, acesso pra sempre).

E tem *garantia de 7 dias*: se não gostar, devolvo 100% do valor.

👉 Aqui o link seguro pra garantir seu acesso:
https://pay.kiwify.com.br/PCQ5TIU`,

  guarantee: `Ah, e só pra reforçar: a garantia é incondicional.

Se em 7 dias você sentir que não valeu, é só me avisar aqui mesmo nesse WhatsApp — devolvo tudo, sem burocracia nenhuma.

O risco é todo meu. 😊`,

  followup24h: `Oi! Tudo bem?

Só passando pra saber se ficou com alguma dúvida sobre o Protocolo Joelho 100%.

Se quiser, posso te explicar melhor como funciona qualquer uma das 4 fases.

Fico à disposição! 😊`,

  followup48h: `Oi! Última mensagem pra não ficar insistente 😄

Se em algum momento quiser fortalecer o joelho com o protocolo, o link continua aqui:
👉 https://pay.kiwify.com.br/PCQ5TIU

Desejo melhoras! Um abraço, Dr. Augusto 🤝`
};

// ── STORAGE EM MEMÓRIA (trocar por Prisma/DB em produção) ──────────
// Estrutura: { "5547999999999": { stage, firstContact, lastMessage, timers } }
const leads = new Map();

// ── ENVIAR MENSAGEM VIA EVOLUTION API ──────────────────────────────

async function sendMessage(instanceName, phone, text) {
  try {
    const r = await fetch(`${EVO_URL}/message/sendText/${instanceName}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": EVO_KEY
      },
      body: JSON.stringify({
        number: phone,
        text: text
      })
    });
    const d = await r.json();
    console.log(`[AutoReply] Enviado para ${phone}: ${text.substring(0, 50)}...`);
    return d;
  } catch (err) {
    console.error(`[AutoReply] Erro ao enviar para ${phone}:`, err.message);
  }
}

// ── AGENDAR MENSAGEM COM DELAY ─────────────────────────────────────

function scheduleMessage(instanceName, phone, text, delayMs, timerId) {
  const lead = leads.get(phone);
  if (!lead) return;

  const timer = setTimeout(async () => {
    const currentLead = leads.get(phone);
    // Só envia se o lead ainda estiver no estágio esperado
    if (currentLead && currentLead.stage !== "needs_human" && currentLead.stage !== "customer") {
      await sendMessage(instanceName, phone, text);
    }
  }, delayMs);

  // Guarda referência do timer pra poder cancelar se necessário
  if (!lead.timers) lead.timers = {};
  lead.timers[timerId] = timer;
}

// ── CANCELAR TODOS OS TIMERS DE UM LEAD ────────────────────────────

function cancelTimers(phone) {
  const lead = leads.get(phone);
  if (lead && lead.timers) {
    Object.values(lead.timers).forEach(t => clearTimeout(t));
    lead.timers = {};
  }
}

// ── PALAVRAS QUE ESCALAM PRA HUMANO ────────────────────────────────

const ESCALATION_WORDS = [
  "cirurgia", "operação", "operei", "operar", "prótese",
  "médico", "ortopedista", "grave", "emergência",
  "reclamar", "reclamação", "reembolso", "devolver", "devolução",
  "cancelar", "cancelamento"
];

function needsHumanEscalation(text) {
  const lower = text.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  return ESCALATION_WORDS.some(word => lower.includes(word));
}

// ── HANDLER PRINCIPAL ──────────────────────────────────────────────

async function handleAutoReply(instanceName, phone, text) {
  // Verifica se autoresponder está ativo
  if (process.env.AUTORESPONDER_ENABLED !== "true") return;

  // Ignora números inválidos
  if (!phone || phone.length < 10) return;

  const now = Date.now();

  // Busca ou cria lead
  let lead = leads.get(phone);

  if (!lead) {
    // ── PRIMEIRO CONTATO ──────────────────────────────────────────
    lead = {
      stage: "new",
      firstContact: now,
      lastMessage: now,
      messageCount: 1,
      timers: {}
    };
    leads.set(phone, lead);

    // Envia boas-vindas (delay de 3s pra parecer humano)
    setTimeout(async () => {
      await sendMessage(instanceName, phone, MESSAGES.welcome);
      lead.stage = "welcome_sent";

      // Agenda follow-ups
      // Follow-up 24h
      scheduleMessage(instanceName, phone, MESSAGES.followup24h, 24 * 60 * 60 * 1000, "followup24h");
      // Follow-up 48h
      scheduleMessage(instanceName, phone, MESSAGES.followup48h, 48 * 60 * 60 * 1000, "followup48h");

    }, 3000);

    return;
  }

  // ── MENSAGENS SUBSEQUENTES ────────────────────────────────────

  lead.lastMessage = now;
  lead.messageCount = (lead.messageCount || 0) + 1;

  // Verifica se precisa escalar pra humano
  if (needsHumanEscalation(text)) {
    lead.stage = "needs_human";
    cancelTimers(phone);
    console.log(`[AutoReply] ⚠️ ESCALAR HUMANO — ${phone}: "${text}"`);
    // Aqui você pode emitir evento via Socket.io pro frontend do CRM
    // io.emit("wa_needs_human", { phone, text });
    return;
  }

  // Se já está marcado como needs_human ou customer, não faz nada
  if (lead.stage === "needs_human" || lead.stage === "customer") return;

  // ── ESTÁGIO: welcome_sent → envia protocolo ──────────────────
  if (lead.stage === "welcome_sent") {

    // Delay de 30s pra parecer que leu e tá digitando
    setTimeout(async () => {
      await sendMessage(instanceName, phone, MESSAGES.protocol);
      lead.stage = "protocol_sent";

      // Envia garantia após 2 minutos
      scheduleMessage(instanceName, phone, MESSAGES.guarantee, 2 * 60 * 1000, "guarantee");

    }, 30 * 1000); // 30 segundos

    return;
  }

  // ── ESTÁGIO: protocol_sent ou guarantee_sent → escala pra humano
  if (lead.stage === "protocol_sent" || lead.stage === "guarantee_sent") {
    // A pessoa já recebeu o fluxo completo e ainda tá mandando mensagem
    // Significa que tem dúvida específica → humano assume
    lead.stage = "needs_human";
    cancelTimers(phone);
    console.log(`[AutoReply] 👤 Lead ${phone} precisa de atendimento humano (pós-fluxo)`);
    // io.emit("wa_needs_human", { phone, text });
    return;
  }
}

// ── MARCAR COMO CLIENTE (chamar quando webhook de compra chegar) ──

function markAsCustomer(phone) {
  const lead = leads.get(phone);
  if (lead) {
    lead.stage = "customer";
    cancelTimers(phone);
    console.log(`[AutoReply] 🎉 ${phone} marcado como cliente`);
  }
}

// ── LIMPAR LEADS ANTIGOS (rodar a cada 24h) ────────────────────────

function cleanupOldLeads() {
  const threeDaysAgo = Date.now() - (3 * 24 * 60 * 60 * 1000);
  for (const [phone, lead] of leads.entries()) {
    if (lead.lastMessage < threeDaysAgo) {
      cancelTimers(phone);
      leads.delete(phone);
    }
  }
}

// Cleanup a cada 6 horas
setInterval(cleanupOldLeads, 6 * 60 * 60 * 1000);

// ── EXPORTA ────────────────────────────────────────────────────────

module.exports = {
  handleAutoReply,
  markAsCustomer,
  MESSAGES,
  leads  // expor pra debug/admin
};
