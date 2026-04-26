Kronova SDK AetherNet API 2.1

to use the SDK....


import { KronovaAgent } from '@kronova-intelligent-systems/kronova-sdk';

const agent = new KronovaAgent({
  supabaseUrl: "https://qcbllcvbwfykbaxzcrwe.supabase.co",
  supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY!,
  agentDid: "did:kronova:supply_chain_agent_01",
  privateKey: process.env.PQC_PRIVATE_KEY!,
  publicKey: process.env.PQC_PUBLIC_KEY!
});

await agent.start();