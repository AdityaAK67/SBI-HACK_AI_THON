# from zapv2 import ZAPv2
# import requests
# from bs4 import BeautifulSoup
# import time
# import json
# import re
# import subprocess
# import os
# import urllib3

# # Disable SSL warnings
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# zap = ZAPv2(apikey='6ik2gkjo3g2unjvnlfu72qq90s', proxies={'http': 'http://localhost:8080'})

# def is_website_reachable(url):
#     try:
#         domain = url.split('//')[-1].split('/')[0]
#         response = subprocess.run(["ping", "-n", "1", domain], capture_output=True, text=True)
#         if "unreachable" in response.stdout.lower() or "could not find host" in response.stdout.lower():
#             print("❌ Website is unreachable.")
#             return False
#         return True
#     except Exception as e:
#         print(f"⚠️ Ping failed: {e}")
#         return False

# def extract_code(url, retries=3, timeout=15):
#     headers = {
#         "User-Agent": "Mozilla/5.0"
#     }

#     for attempt in range(retries):
#         try:
#             response = requests.get(url, headers=headers, timeout=timeout)
#             response.raise_for_status()
#             soup = BeautifulSoup(response.text, "html.parser")
#             scripts = [s.string for s in soup.find_all("script") if s.string]
#             return {"html": soup.prettify(), "js": scripts}
#         except requests.exceptions.RequestException as e:
#             print(f"⚠️ Attempt {attempt + 1} failed: {e}")
#             time.sleep(2)  # wait before retry
#         except Exception as e:
#             print(f"❌ Unexpected error: {e}")
#             break

#     print("❌ All attempts to extract code failed.")
#     return None

# def sanitize_filename(url):
#     return re.sub(r'[\\/*?:"<>|]', "_", url)

# def deduplicate_alerts(alerts):
#     seen = {}
#     for a in alerts:
#         key = (a.get("alert"), a.get("url"), a.get("param"))
#         if key not in seen:
#             seen[key] = a
#     return list(seen.values())

# def generate_html_report(alerts, target_url, filename):
#     severity_classes = {
#         "High": "high", "Medium": "medium", "Low": "low", "Informational": "info"
#     }

#     html = f"""<!DOCTYPE html><html><head>
#     <meta charset="UTF-8"><title>ZAP Scan Report</title>
#     <style>
#     body {{ font-family: Arial; padding: 20px; }}
#     .alert {{ border: 1px solid #ccc; padding: 10px; margin-bottom: 15px; border-radius: 5px; }}
#     .high {{ background-color: #f8d7da; }}
#     .medium {{ background-color: #fff3cd; }}
#     .low {{ background-color: #d1ecf1; }}
#     .info {{ background-color: #e2e3e5; }}
#     </style>
#     </head><body>
#     <h1>🔍 ZAP Scan Report</h1><p><b>Target:</b> {target_url}</p>
#     <p><b>Vulnerabilities Found:</b> {len(alerts)}</p>
#     """

#     for a in alerts:
#         level = a.get("risk", "Informational")
#         style = severity_classes.get(level, "info")
#         html += f"""<div class='alert {style}'>
#         <h2>{a.get("alert", "Unknown")}</h2>
#         <p><b>Risk:</b> {level}</p>
#         <p><b>Description:</b> {a.get("description", "No description")}</p>
#         <p><b>URL:</b> {a.get("url")}</p>
#         <p><b>Param:</b> {a.get("param", "N/A")}</p>
#         <p><b>Solution:</b> {a.get("solution", "N/A")}</p>
#         </div>"""

#     html += "</body></html>"
#     with open(filename, "w", encoding="utf-8") as f:
#         f.write(html)
#     print(f"📄 HTML report saved to: {filename}")

# def save_scan_results(alerts, target):
#     # Define the fixed file path where the scan results should be saved
#     output_path = r"D:\sbi_hack_ai_thon 24\AK\src\data\zap_scan_results.json"

#     try:
#         # Remove old file if it exists
#         if os.path.exists(output_path):
#             os.remove(output_path)
#             print("🧹 Old scan result removed.")
#         else:
#             print("ℹ️ No previous scan result found. Creating a new one.")

#         # Write new data
#         with open(output_path, "w") as f:
#             json.dump(alerts, f, indent=4)
#         print(f"📁 JSON scan results saved to: {output_path}")

#     except Exception as e:
#         print(f"❌ Failed to save scan results: {e}")


# # ========== MAIN ==========
# target = input("Enter target URL: ").strip()

# # Ensure the URL starts with https:// or http://
# if not target.startswith("http://") and not target.startswith("https://"):
#     target = "https://" + target

# print(f"Using target URL: {target}")

# if not is_website_reachable(target):
#     print("❌ Exiting: Website not reachable.")
#     exit()

# print(f"\n📥 Extracting code from {target}...")
# website_code = extract_code(target)
# if not website_code:
#     print("❌ Failed to extract code.")
#     exit()
# print("✅ Code extracted.")


# # Reduce spider depth
# print("\n🕷️ Starting spider scan (depth=2)...")
# zap.spider.set_option_max_depth(2)
# zap.spider.scan(target)
# while int(zap.spider.status()) < 100:
#     print(f"Spider progress: {zap.spider.status()}%")
#     time.sleep(1)
# print("✅ Spider scan completed.")

# # Start active scan
# print("\n🔥 Starting active scan...")
# scan_id = zap.ascan.scan(target)
# while int(zap.ascan.status(scan_id)) < 100:
#     print(f"Active scan: {zap.ascan.status(scan_id)}%")
#     time.sleep(2)
# print("✅ Active scan done.")

# # Fetch and save alerts
# print("\n🛡️ Fetching alerts...")
# alerts = zap.core.alerts()
# unique_alerts = deduplicate_alerts(alerts)
# print(f"🔍 Found {len(unique_alerts)} unique issues.")

# # Save results
# save_scan_results(unique_alerts, target)

# # Save HTML report
# html_file = f"zap_report_{sanitize_filename(target)}.html"
# generate_html_report(unique_alerts, target, html_file)

# print("\n🎯 Scan complete!")





from zapv2 import ZAPv2
import requests
from bs4 import BeautifulSoup
import time
import json
import re
import subprocess
import os
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

zap = ZAPv2(apikey='397p2anu0i3jlji41me9br6ug0', proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})

def is_website_reachable(url):
    try:
        domain = url.split('//')[-1].split('/')[0]
        response = subprocess.run(["ping", "-n", "1", domain], capture_output=True, text=True)
        if "unreachable" in response.stdout.lower() or "could not find host" in response.stdout.lower():
            print("\u274c Website is unreachable.")
            return False
        return True
    except Exception as e:
        print(f"\u26a0\ufe0f Ping failed: {e}")
        return False

def extract_code(url, retries=3, timeout=15):
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            scripts = [s.string for s in soup.find_all("script") if s.string]
            return {"html": soup.prettify(), "js": scripts}
        except requests.exceptions.RequestException as e:
            print(f"\u26a0\ufe0f Attempt {attempt + 1} failed: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"\u274c Unexpected error: {e}")
            break
    print("\u274c All attempts to extract code failed.")
    return None

def sanitize_filename(url):
    return re.sub(r'[\\/*?:"<>|]', "_", url)

def deduplicate_alerts(alerts):
    seen = {}
    for a in alerts:
        key = (a.get("alert"), a.get("url"), a.get("param"))
        if key not in seen:
            seen[key] = a
    return list(seen.values())

def generate_html_report(alerts, target_url, filename):
    severity_classes = {
        "High": "high", "Medium": "medium", "Low": "low", "Informational": "info"
    }

    html = f"""<!DOCTYPE html><html><head>
    <meta charset="UTF-8"><title>ZAP Scan Report</title>
    <style>
    body {{ font-family: Arial; padding: 20px; }}
    .alert {{ border: 1px solid #ccc; padding: 10px; margin-bottom: 15px; border-radius: 5px; }}
    .high {{ background-color: #f8d7da; }}
    .medium {{ background-color: #fff3cd; }}
    .low {{ background-color: #d1ecf1; }}
    .info {{ background-color: #e2e3e5; }}
    </style>
    </head><body>
    <h1>🔍 ZAP Scan Report</h1><p><b>Target:</b> {target_url}</p>
    <p><b>Vulnerabilities Found:</b> {len(alerts)}</p>
    """

    for a in alerts:
        level = a.get("risk", "Informational")
        style = severity_classes.get(level, "info")
        html += f"<div class='alert {style}'>\
        <h2>{a.get('alert', 'Unknown')}</h2>\
        <p><b>Risk:</b> {level}</p>\
        <p><b>Description:</b> {a.get('description', 'No description')}</p>\
        <p><b>URL:</b> {a.get('url')}</p>\
        <p><b>Param:</b> {a.get('param', 'N/A')}</p>\
        <p><b>Solution:</b> {a.get('solution', 'N/A')}</p>\
        </div>"

    html += "</body></html>"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"📄 HTML report saved to: {filename}")

def save_scan_results(alerts):
    output_path = r"D:\\sbi_hack_ai_thon 24\\AK\\src\\data\\zap_scan_results.json"
    try:
        if os.path.exists(output_path):
            os.remove(output_path)
            print("\U0001f9f9 Old scan result removed.")
        else:
            print("\u2139\ufe0f No previous scan result found. Creating a new one.")

        with open(output_path, "w") as f:
            json.dump(alerts, f, indent=4)
        print(f"\ud83d\udcc1 JSON scan results saved to: {output_path}")
    except Exception as e:
        print(f"\u274c Failed to save scan results: {e}")

# MAIN
if __name__ == '__main__':
    target = input("Enter target URL: ").strip()

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    print(f"Using target URL: {target}")

    if not is_website_reachable(target):
        print("\u274c Exiting: Website not reachable.")
        exit()

    print(f"\n📅 Extracting code from {target}...")
    website_code = extract_code(target)
    if not website_code:
        print("\u274c Failed to extract code.")
        exit()
    print("\u2705 Code extracted.")

    print("\n🕷️ Starting spider scan (depth=2)...")
    zap.spider.set_option_max_depth(2)
    zap.spider.scan(target)
    while int(zap.spider.status()) < 100:
        print(f"Spider progress: {zap.spider.status()}%")
        time.sleep(1)
    print("\u2705 Spider scan completed.")

    print("\n🔥 Starting active scan...")
    scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Active scan: {zap.ascan.status(scan_id)}%")
        time.sleep(2)
    print("\u2705 Active scan done.")

    print("\n🛡️ Fetching alerts...")
    alerts = zap.core.alerts()
    unique_alerts = deduplicate_alerts(alerts)
    print(f"🔍 Found {len(unique_alerts)} unique issues.")

    save_scan_results(unique_alerts)

    html_file = f"zap_report_{sanitize_filename(target)}.html"
    generate_html_report(unique_alerts, target, html_file)

    print("\n🎯 Scan complete!")
