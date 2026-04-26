
import { z } from 'zod';
// 1. Remove "type" from the import. We need the actual Zod runtime objects to infer from and validate against.
import { AP2CartSchema, AP2PaymentSchema } from '../types/schemas';
import { AetherTransport } from '../network/transport';
import { CryptoEngine } from '../security/crypto';

// 2. Extract the clean TypeScript data interfaces from the Zod schemas
type AP2Cart = z.infer<typeof AP2CartSchema>;
type AP2Payment = z.infer<typeof AP2PaymentSchema>;

export class AP2Wallet {
  constructor(private transport: AetherTransport, private crypto: CryptoEngine) {}

  // 3. Type the parameter as the raw data (AP2Cart), not the Zod validator
  async pay(cart: AP2Cart) {
    
    // 4. Type the object as the raw data (AP2Payment)
    const paymentData: AP2Payment = {
      type: 'AP2_PAYMENT',
      intent_ref: cart.intent_ref,
      cart_ref: cart.cart_id,
      final_amount: cart.total_amount,
      agent_signature: ""
    };

    // 5. Sign the payload (CryptoEngine handles the deterministic JSON stringification)
    paymentData.agent_signature = this.crypto.sign(paymentData);

    // 6. Enterprise Safety Check: Run the final constructed object through the Zod validator
    // This guarantees the payload exactly matches what the Rust TEE and Canton smart contracts expect.
    const validatedPayment = AP2PaymentSchema.parse(paymentData);

   // 7. Fire the perfectly shaped TransportMessage object
    return this.transport.sendMessage({
      recipient_did: "SETTLEMENT_GATEWAY", // The target node DID
      metadata: { payload_type: 'ap2_mandate', mandate_step: 'payment' },
      payload: this.crypto.encrypt(validatedPayment, "YOUR_GATEWAY_KYBER_PUBLIC_KEY")
    });
  }
}