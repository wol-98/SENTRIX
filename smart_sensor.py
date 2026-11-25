import requests
import time
import random
from config import Config

# SERVER URL
URL = "http://127.0.0.1:5001/api/telemetry"
if not Config.API_SECRET_KEY:
    raise RuntimeError("API_SECRET_KEY is missing from .env")

HEADERS = {"X-API-Key": Config.API_SECRET_KEY}

print("🤖 SMART AI SIMULATION STARTED (THREAT SIMULATION)")
print("--------------------------------")
print("✅ Simulating: Safe, Fire, Intruder, and OVERHEAT")
print("--------------------------------")

EVENT_DURATION = 0 
CURRENT_STATE = "SAFE" 

while True:
    # 1. LOGIC ENGINE
    if CURRENT_STATE == "SAFE":
        chance = random.randint(1, 100)
        
        if chance <= 5: 
            CURRENT_STATE = "FIRE"
            EVENT_DURATION = 10 
            print("\n🔥 SUDDEN EVENT: Fire Started!")
            
        elif chance <= 10: 
            CURRENT_STATE = "MOTION"
            EVENT_DURATION = 10 
            print("\n👀 SUDDEN EVENT: Intruder Detected!")

        elif chance <= 15: # New Event
            CURRENT_STATE = "OVERHEAT"
            EVENT_DURATION = 15
            print("\n♨️ SUDDEN EVENT: Server Overheating (No Fire)")
            
        else:
            print(".", end="", flush=True)

    else:
        EVENT_DURATION -= 1
        print(f"⚠️ {CURRENT_STATE} IN PROGRESS... ({EVENT_DURATION}s remaining)")
        
        if EVENT_DURATION <= 0:
            print(f"✅ Event Ended. System Returning to Safe.")
            CURRENT_STATE = "SAFE"

    # 2. GENERATE DATA
    if CURRENT_STATE == "SAFE":
        temp = round(random.uniform(22.0, 25.0), 1)
        gas = random.randint(150, 300)
        motion = 0

    elif CURRENT_STATE == "FIRE":
        temp = round(random.uniform(60.0, 80.0), 1)
        gas = random.randint(1200, 2000) # High Gas
        motion = 0

    elif CURRENT_STATE == "MOTION":
        temp = round(random.uniform(22.0, 25.0), 1)
        gas = random.randint(150, 300)
        motion = 1 

    elif CURRENT_STATE == "OVERHEAT":
        # High Temp, BUT Low Gas (This is the key for Crypto Detection)
        temp = round(random.uniform(45.0, 55.0), 1) 
        gas = random.randint(150, 300) 
        motion = 0

    payload = {
        "temperature": temp,
        "gas": gas,
        "motion": motion
    }

    try:
        requests.post(URL, json=payload, headers=HEADERS)
    except:
        pass

    time.sleep(1)