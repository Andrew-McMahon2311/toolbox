import asyncio
import argparse
import json
import aiohttp
import dns.asyncresolver

async def get_crush_subdomains(domain, session):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    try:
        async with session.get(url, timeout=19) as resp:
            if resp.status == 200:
                data = await resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and not sub.startswith('*'):
                            subdomains.add(sub)
    except Exception:
        pass
    return subdomains

async def resolve_subdomain(subdomain, resolver):
    try:
        answers = await resolver.resolve(subdomain, 'A')
        return subdomain, [ip.to_text() for ip in answers]
    except Exception:
        return subdomain, None

async def check_http(subdomain, session):
    for scheme in ['https', 'http']:
        url = f"{scheme}://{subdomain}"
        try:
            async with session.get(url, timeout=3, allow_redirects=True) as resp:
                return scheme, resp.status
        except Exception:
            continue
    return None, None

async def process_subdomain(subdomain, resolver, session, semaphore):
    async with semaphore:
        _, ips = await resolve_subdomain(subdomain, resolver)
        if not ips:
            return None
        
        scheme, status = await check_http(subdomain, session)
        return {
            "subdomain": subdomain,
            "ips": ips,
            "live": status is not None,
            "status_code": status,
            "protocol": scheme
        }

async def main():
    parser = argparse.ArgumentParser(description="Async Subdomain Recon & Prober Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Max concurrent tasks")
    args = parser.parse_args()

    target_domain = args.domain.lower()
    candidate_subdomains = set()

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        print(f"[*] Fetching passive subdomains from crt.sh for {target_domain}...")
        crt_subs = await get_crush_subdomains(target_domain, session)
        candidate_subdomains.update(crt_subs)
        print(f"[+] Found {len(crt_subs)} subdomains from CT logs.")

        if args.wordlist:
            try:
                with open(args.wordlist, 'r') as f:
                    for line in f:
                        sub = line.strip().lower()
                        if sub:
                            candidate_subdomains.add(f"{sub}.{target_domain}")
            except Exception as e:
                print(f"[!] Error reading wordlist: {e}")

        print(f"[*] Resolving and probing {len(candidate_subdomains)} unique targets...")
        semaphore = asyncio.Semaphore(args.concurrency)
        tasks = [process_subdomain(sub, resolver, session, semaphore) for sub in candidate_subdomains]
        
        results = []
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res:
                results.append(res)
                status_str = f"[{res['protocol'].upper()} {res['status_code']}]" if res['live'] else "[No HTTP]"
                print(f"[+] {res['subdomain']:<35} -> IPs: {', '.join(res['ips'])} {status_str}")

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n[*] Saved {len(results)} active subdomains to {args.output}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Exiting...")