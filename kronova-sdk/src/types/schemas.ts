import { z } from "zod";

export const AP2IntentSchema = z.object({
  type: z.literal("AP2_INTENT"),
  mandate_id: z.string(),
  issuer: z.string(),
  delegate: z.string(),
  constraints: z.object({
    max_amount: z.number().positive(),
    currency: z.literal("USDCx"),
    expires_at: z.string().datetime()
  })
});

export const AP2CartSchema = z.object({
  type: z.literal("AP2_CART"),
  cart_id: z.string(),
  intent_ref: z.string(), // Links to Intent ID
  items: z.array(z.object({ desc: z.string(), qty: z.number(), unit_price: z.number() })),
  total_amount: z.number().positive()
});

export const AP2PaymentSchema = z.object({
  type: z.literal("AP2_PAYMENT"),
  intent_ref: z.string(),
  cart_ref: z.string(), // Links to Cart ID
  final_amount: z.number().positive(),
  agent_signature: z.string()
});