import { z } from "zod";

export const AP2IntentSchema = z.object({
  type: z.literal("AP2_INTENT"),
  mandate_id: z.string(),
  issuer: z.string(),
  delegate: z.string(),
  constraints: z.object({
    max_amount: z.number().positive(),
    currency: z.enum(["USDCx", "EURx", "USD"]),
    expires_at: z.string().datetime(),
  }),
});

export const AP2CartItemSchema = z.object({
  desc: z.string(),
  qty: z.number().positive(),
  unit_price: z.number().nonnegative(),
});

export const AP2CartSchema = z.object({
  type: z.literal("AP2_CART"),
  cart_id: z.string(),
  intent_ref: z.string(),
  items: z.array(AP2CartItemSchema).max(500),
  total_amount: z.number().positive(),
});

export const AP2PaymentSchema = z.object({
  type: z.literal("AP2_PAYMENT"),
  intent_ref: z.string(),
  cart_ref: z.string(),
  final_amount: z.number().positive(),
  agent_signature: z.string(),
});

export type AP2Intent = z.infer<typeof AP2IntentSchema>;
export type AP2Cart = z.infer<typeof AP2CartSchema>;
export type AP2Payment = z.infer<typeof AP2PaymentSchema>;