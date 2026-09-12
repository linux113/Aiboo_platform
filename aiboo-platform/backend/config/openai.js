import OpenAI from 'openai';
import 'dotenv/config';

const apiKey = process.env.OPENAI_KEY || '';
const isGroq = apiKey.startsWith('gsk_');

export const openai = new OpenAI({
  apiKey,
  baseURL: isGroq ? 'https://api.groq.com/openai/v1' : undefined,
});

export const CHAT_MODEL = isGroq ? 'llama3-8b-8192' : 'gpt-4o-mini';
