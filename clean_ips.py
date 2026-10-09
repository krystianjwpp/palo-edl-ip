import ipaddress
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# The 7 working feeds verified on your test box (Cisco Talos removed)
edl_feeds = {
    "DShield Block": "https://dshield.org",
    "GreenSnow": "https://greensnow.co",
    "Spamhaus DROP": "https://spamhaus.org",
    "FireHOL Level 1": "https://githubusercontent.com",
    "Emerging Threats Known": "https://opendbl.net",
    "IPSum Master": "https://opendbl.net",
    "OpenDBL High-Confidence": "https://opendbl.net",
    "FireHOL Level 3": "https://githubusercontent.com"
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
            if not line or line.startswith('#') or line.startswith(';'):
                continue
                
            tokens = line.split()
            if not tokens:
                continue
                
            # Parse DShield or standard format tokens
            if len(tokens) >= 3 and tokens[2].isdigit() and int(tokens[2]) <= 32:
                ip_candidate = f"{tokens[0]}/{tokens[2]}"
            else:
                first_item = tokens[0]
                if '#' in first_item:
                    first_item = first_item.split('#')[0]
                if ';' in first_item:
                    first_item = first_item.split(';')[0]
                ip_candidate = first_item.strip()
                
            try:
                net_obj = ipaddress.ip_network(ip_candidate, strict=False)
                # Drop routing bug vectors (private / loopback blocks)
                if net_obj.is_private or net_obj.is_loopback:
                    continue
                raw_networks.append(net_obj)
            except ValueError:
                continue
                
    except Exception as e:
        print(f" ❌ Error processing {feed_name}: {str(e)}")

print(f"📊 Raw network fragments collected: {len(raw_networks):,}")

print("🧼 Executing topological block-merge reduction...")
optimized_networks = list(ipaddress.collapse_addresses(raw_networks))

# Save the final flat list
with open("./pa-master-ip-blocklist.txtt", "w") as f:
    for net in optimized_networks:
        f.write(f"{net}\n")

print(f"✅ Success! Generated optimized master blocklist size: {len(optimized_networks):,} records.")
