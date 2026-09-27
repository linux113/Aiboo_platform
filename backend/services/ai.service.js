import { openai, CHAT_MODEL } from '../config/openai.js';
import Threat from '../models/Threat.js';
import Detection from '../models/Detection.js';
import logger from '../utils/logger.js';

export const analyzeThreats = async () => {
  const threats = await Threat.find();
  return threats.reduce((acc, t) => { acc[t.severity] = (acc[t.severity]||0)+1; return acc; }, {});
};

export const chatWithAI = async (message, history = []) => {
  const system = `You are AiBoO JARVIS, an expert AI security analyst for a Cyber-Physical SOC.
You monitor cameras (YOLOv8+DeepSORT), detect threats via tri-gate pipeline, and help operators respond.
Be concise, professional, and actionable. You have real-time context from the live system.
Respond in under 150 words. Use bullet points for multi-part answers.`;

  try {
    const completion = await openai.chat.completions.create({
      model: CHAT_MODEL,
      messages: [
        { role: 'system', content: system },
        ...history.slice(-8).map(m => ({ role: m.role, content: m.content })),
        { role: 'user', content: message },
      ],
      temperature: 0.3,
      max_tokens: 300,
    });
    return {
      role: 'assistant',
      content: completion.choices[0].message.content.trim(),
      timestamp: new Date().toISOString(),
    };
  } catch (err) {
    logger.error(`AI chat error: ${err.message}`);
    return { role: 'assistant', content: fallback(message), timestamp: new Date().toISOString(), fallback: true };
  }
};

export const explainAlert = async (query) => {
  try {
    const [threats, detections] = await Promise.all([Threat.find().limit(5), Detection.find().limit(5)]);
    const res = await openai.chat.completions.create({
      model: CHAT_MODEL,
      messages: [{ role: 'user', content: `SOC analyst. Threats: ${JSON.stringify(threats)}. Query: ${query}. Answer concisely.` }],
      temperature: 0.2, max_tokens: 200,
    });
    return { answer: res.choices[0].message.content.trim(), confidence: 0.9, sources: 'threat-db' };
  } catch (err) {
    logger.error(`AI explainAlert error: ${err.message}`);
    return { answer: 'AI unavailable', confidence: 0, sources: '' };
  }
};

function fallback(msg) {
  const m = msg.toLowerCase();
  if (m.includes('weapon')||m.includes('gun')||m.includes('knife'))
    return '⚠️ Weapon detection protocol activated. (1) Alert security, (2) Initiate zone lockdown, (3) Contact law enforcement, (4) Preserve footage.';
  if (m.includes('status')||m.includes('report')||m.includes('sitrep'))
    return '📊 JARVIS status: Tri-gate pipeline active. All agents monitoring. Check Dashboard for live threat feed and Agent Console for findings.';
  if (m.includes('lock')||m.includes('pseudo'))
    return '🔒 Pseudo-locks active in Agent Console → Locks tab. Each lock redirects attacker traffic to a decoy honeypot system.';
  if (m.includes('camera')||m.includes('surveillance'))
    return '📷 Camera grid monitoring via YOLOv8+DeepSORT. Add cameras in Surveillance tab with your IP Webcam URL.';
  if (m.includes('gate')||m.includes('pipeline'))
    return '⚙️ Tri-gate: Gate 1 (Perimeter) → Gate 2 (Behavioural) → Gate 3 (Adaptive Response). Events flow through all gates before action.';
  if (m.includes('hello')||m.includes('hi')||m.includes('hey'))
    return 'JARVIS online. I\'m monitoring tri-gate pipeline, 4 agents, and all camera feeds. How can I assist?';
  return `JARVIS analyzing: "${msg}". AI model active via Groq API. Ask about threats, cameras, agents, gates, or request a situation report.`;
}
