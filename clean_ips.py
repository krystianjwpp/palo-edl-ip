import ipaddress
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# The exact 8 source URLs you provided
# Mapped active intelligence streams with your 4 new OpenDBL targets included
edl_feeds = {
    "DShield Block": "https://dshield.org",
    "GreenSnow": "https://greensnow.co",
    "Spamhaus DROP": "https://spamhaus.org",
    "FireHOL Level 1": "https://githubusercontent.com",
    "Emerging Threats Known": "https://opendbl.net",
    "IPSum Master": "https://opendbl.net/lists/ipsum.list",
    "OpenDBL High-Confidence": "https://opendbl.net",
    "FireHOL Level 3": "https://githubusercontent.com",
    # --- YOUR NEW TARGET SOURCES ADDED BELOW ---
    "ThreatFox C2 & Payload": "https://opendbl.net/lists/threatfox.list",
    "Blocklist.de All": "https://opendbl.net/lists/blocklistde-all.list",
    "DShield Expanded": "https://opendbl.net/lists/dshield-expanded.list",
    "OpenDBL Broad-Coverage": "https://opendbl.net/lists/broad-coverage.list"
}

raw_networks = []

print("🚀 Starting Master IP Threat Intelligence Aggregation...")

for feed_name, url in edl_feeds.items():
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code != 200:
            print(f" ⚠️ Skipping {feed_name}: HTTP {response.status_code}")
            continue
            
        lines = response.text.splitlines()
        for line in lines:
            line = line.strip()
            
            # Skip empty lines or standard doc headers
            if not line or line.startswith('#') or line.startswith(';'):
                continue
                
            # Clean inline comments securely without throwing list token errors
            # E.g., '1.10.16.0/20 ; SBL256894' -> '1.10.16.0/20'
            clean_line = line.split('#')[0].split(';')[0].strip()
            if not clean_line:
                continue
                
            # Tokenize row contents by any whitespace block
            tokens = clean_line.split()
            if not tokens:
                continue
                
            # 1. Custom handler for DShield's multi-column mask layout (Base_IP + Mask Column)
            if len(tokens) >= 3 and tokens[2].isdigit() and int(tokens[2]) <= 32:
                ip_candidate = f"{tokens[0]}/{tokens[2]}"
            else:
                # 2. Extract first token for standard hosts or raw CIDR strings
                ip_candidate = tokens[0]
                
            try:
                net_obj = ipaddress.ip_network(ip_candidate, strict=False)
                
                # Exclude internal local loopbacks or private address maps safely
                if net_obj.is_private or net_obj.is_loopback:
                    continue
                raw_networks.append(net_obj)
            except ValueError:
                continue
                
    except Exception as e:
        print(f" ❌ Error processing {feed_name}: {str(e)}")

print(f"📊 Raw network fragments collected: {len(raw_networks):,}")

# Math super-set collapse: Condenses duplicates and optimizes subnet blocks
print("🧼 Executing topological block-merge reduction...")
optimized_networks = list(ipaddress.collapse_addresses(raw_networks))

# Write out the single streamlined production blocklist file straight to workspace root
with open("pa-master-ip-blocklist.txt", "w") as f:
    for net in optimized_networks:
        f.write(f"{net}\n")

print(f"✅ Success! Generated master blocklist with {len(optimized_networks):,} optimized entries.")
