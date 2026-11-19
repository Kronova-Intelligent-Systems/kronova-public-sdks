import {
  AP2CartSchema,
  AP2PaymentSchema,
  type AP2Cart,
  type AP2Payment,
} from "../types/schemas";
import { AetherTransport } from "../network/transport";
import { CryptoEngine } from "../security/crypto";

export interface PayCartOptions {
  recipientDid?: string;
  recipientKyberPubB64: string;
}

export class AP2Wallet {
  constructor(
    private transport: AetherTransport,
    private crypto: CryptoEngine
  ) {}

  async pay(cart: AP2Cart, options: PayCartOptions) {
    const validCart = AP2CartSchema.parse(cart);

    const unsignedPayment = {
      type: "AP2_PAYMENT" as const,
      intent_ref: validCart.intent_ref,
      cart_ref: validCart.cart_id,
      final_amount: validCart.total_amount,
      agent_signature: "",
    };

    const signature = await this.crypto.sign(unsignedPayment);

    const validatedPayment: AP2Payment = AP2PaymentSchema.parse({
      ...unsignedPayment,
      agent_signature: signature,
    });

    const sealedPayload = await this.crypto.encrypt(
      validatedPayment,
      options.recipientKyberPubB64
    );

    return this.transport.sendMessage({
      recipient_did: options.recipientDid ?? "SETTLEMENT_GATEWAY",
      metadata: { payload_type: "ap2_mandate", mandate_step: "payment" },
      payload: sealedPayload,
    });
  }
}