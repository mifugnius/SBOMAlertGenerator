import asyncio
import aiohttp
import json

async def fetch_single_osv(session, vuln_id):
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    try:
        async with session.get(url) as response:
            if response.status == 200:
                return await response.json()
            
            else:
                print(f"Error for {vuln_id}: {response.status}")
    except Exception as e:
        print(f"Exception for {vuln_id}: {e}")


async def query_vulnerability_info_from_osv_by_ids(ids):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_single_osv(session, vuln_id) for vuln_id in ids]
        results = await asyncio.gather(*tasks)
        return results