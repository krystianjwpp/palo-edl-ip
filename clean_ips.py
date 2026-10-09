import ipaddress
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# The exact 8 source URLs you provided
edl_feeds = {
    "DShield Block": "https://www.dshield.org/block.txt",
    "GreenSnow": "https://blocklist.greensnow.co/greensnow.txt",
    "Spamhaus DROP": "https://www.spamhaus.org/drop/drop.txt",
    "FireHOL Level 1": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "Emerging Threats Known": "https://opendbl.net/lists/etknown.list",
    "IPSum Master": "https://opendbl.net/lists/ipsum.list",
    "OpenDBL High-Confidence": "https://opendbl.net/lists/high-confidence.list",
    "FireHOL Level 3": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_level3.netset"
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
