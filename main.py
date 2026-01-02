import requests
import json
import time
from packaging.version import Version, InvalidVersion

# ==============================
# CONFIG
# ==============================
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cve/2.0"

# ==============================
# VERSION UTILS
# ==============================
def safe_version(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None

def version_in_range(user_v, start_inc, start_exc, end_inc, end_exc):
    user_v = safe_version(user_v)
    if not user_v:
        return False

    if start_inc and user_v < Version(start_inc):
        return False
    if start_exc and user_v <= Version(start_exc):
        return False
    if end_inc and user_v > Version(end_inc):
        return False
    if end_exc and user_v >= Version(end_exc):
        return False

    return True

# ==============================
# FETCH KEV DATA
# ==============================
def fetch_kev_data():
    response = requests.get(KEV_URL, timeout=20)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

# ==============================
# FETCH NVD VERSION DATA
# ==============================
def fetch_nvd_versions(cve_id):
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        timeout=20
    )

    if response.status_code != 200:
        return []

    data = response.json()
    ranges = []

    try:
        nodes = data["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"]
        for node in nodes:
            for cpe in node.get("cpeMatch", []):
                ranges.append({
                    "startIncluding": cpe.get("versionStartIncluding"),
                    "startExcluding": cpe.get("versionStartExcluding"),
                    "endIncluding": cpe.get("versionEndIncluding"),
                    "endExcluding": cpe.get("versionEndExcluding"),
                })
    except (KeyError, IndexError):
        pass

    time.sleep(1)  # Respect NVD rate limits
    return ranges

# ==============================
# MAIN LOGIC
# ==============================
def main():
    software = input("Enter software name: ").strip().lower()
    version = input("Enter software version: ").strip()

    user_version = safe_version(version)
    if not user_version:
        print("❌ Invalid version format.")
        return

    keywords = software.split()
    kev_vulns = fetch_kev_data()
    found = False

    for vuln in kev_vulns:
        product = vuln.get("product", "").lower()
        vendor = vuln.get("vendorProject", "").lower()

        if not any(k in product or k in vendor for k in keywords):
            continue

        cve_id = vuln.get("cveID")
        print(f"\n🔍 Checking {cve_id}")

        version_ranges = fetch_nvd_versions(cve_id)

        affected = False
        if not version_ranges:
            affected = True
        else:
            for r in version_ranges:
                if version_in_range(
                    version,
                    r["startIncluding"],
                    r["startExcluding"],
                    r["endIncluding"],
                    r["endExcluding"],
                ):
                    affected = True
                    break

        if affected:
            found = True
            print("\n⚠️ AFFECTED VERSION FOUND (KEV + NVD)\n")
            for k, v in vuln.items():
                print(f"{k}: {v}")
            print("=" * 60)

    if not found:
        print("\n✅ No matching KEV + NVD vulnerabilities found.")

# ==============================
# ENTRY POINT
# ==============================
if __name__ == "__main__":
    main()
