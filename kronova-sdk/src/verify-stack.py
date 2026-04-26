def send_ap2_intent():
    """Injects a v2.1 AP2 Intent into the AetherNet message stream."""
    url = f"{SUPABASE_URL}/rest/v1/aethernet_messages"
    
    payload = {
        "id": str(uuid.uuid4()),
        "protocol_version": "2.1", # <--- NEW: Enforcing v2.1
        "sender_id": SENDER_ID,
        "message_type": "ap2_mandate",
        "priority": "high",
        "status": "queued",
        "metadata": {
            "payload_type": "ap2_mandate",
            "mandate_step": "intent",
            "test_run": TEST_RUN_ID
        },
        # In a real scenario, this is E2EE. For the DB test, we inject the raw JSON.
        "content": json.dumps({
            "type": "AP2_INTENT",
            "mandate_id": MANDATE_ID,
            "constraints": {
                "max_amount": "50.00",
                "currency": "USDCx"
            }
        })
    }
    
    resp = requests.post(url, headers=HEADERS, json=payload)
    return resp.status_code in [200, 201]

def verify_mandate_creation():
    """Verifies that the database trigger successfully populated the AP2 table."""
    url = f"{SUPABASE_URL}/rest/v1/aethernet_ap2_mandates"
    params = {"issuer_did": f"eq.{SENDER_ID}", "select": "id,status"}
    
    resp = requests.get(url, headers=HEADERS, params=params)
    if resp.status_code == 200 and len(resp.json()) > 0:
        log(3, "✅ AP2 Mandate successfully indexed in relational table.")
        return True
    return False