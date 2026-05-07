import re
from collections import defaultdict

# ---------------- USER INPUT ----------------
log_file = input("Enter log file (default: logs.txt): ").strip().lower() or "logs.txt"

try:
    THRESHOLD = int(input("Enter threshold (default: 3): ") or 3)
except:
    THRESHOLD = 3

save_report = input("Save report? (yes/no): ").lower() == "yes"

# ---------------- DATA STRUCTURES ----------------
failed_attempts = defaultdict(int)
successful_logins = defaultdict(int)
attack_after_success = []

ip_pattern = r"\d+\.\d+\.\d+\.\d+"

# ---------------- READ FILE ----------------
try:
    with open(log_file, "r") as file:
        lines = file.readlines()
except FileNotFoundError:
    print("Error: File not found.")
    exit()

# ---------------- PROCESS LOGS ----------------
for line in lines:
    ip_match = re.search(ip_pattern, line)
    if not ip_match:
        continue

    ip = ip_match.group()

    if "failed" in line.lower():
        failed_attempts[ip] += 1

    elif "accepted" in line.lower():
        successful_logins[ip] += 1

        # Detect suspicious success after failures
        if failed_attempts[ip] >= THRESHOLD:
            attack_after_success.append(ip)

# ---------------- OUTPUT ----------------
print("\n==============================")
print("   LOG ANALYSIS REPORT")
print("==============================")

# -------- FAILED ATTEMPTS --------
print("\n[1] Failed Login Attempts:")
if failed_attempts:
    for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
        if count >= 2:
            word = "attempt" if count == 1 else "attempts"
            print(f"  - {ip} → {count} {word}")
else:
    print("  No failed attempts found")

# -------- SMART SEVERITY ANALYSIS --------
print("\n[2] Suspicious Activity Analysis:")

flagged = False

for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        print(f"  [HIGH] {ip} → {count} attempts (Brute Force)")
        flagged = True
    elif count >= 5:
        print(f"  [MEDIUM] {ip} → {count} attempts (Suspicious)")
        flagged = True
    elif count >= 3:
        print(f"  [LOW] {ip} → {count} attempts (Unusual)")
        flagged = True

if not flagged:
    print("  No suspicious activity detected")

# -------- SUCCESSFUL LOGINS --------
print("\n[3] Successful Logins:")
if successful_logins:
    for ip, count in successful_logins.items():
        word = "login" if count == 1 else "logins"
        print(f"  - {ip} → {count} successful {word}")
else:
    print("  No successful logins")

# -------- SUCCESS AFTER FAILURE --------
print("\n[4] Success After Multiple Failures:")
if attack_after_success:
    for ip in set(attack_after_success):
        print(f"  [CRITICAL] {ip} (possible account compromise)")
else:
    print("  No suspicious success patterns detected")

# -------- TOP ATTACKER --------
if failed_attempts:
    top_ip = max(failed_attempts, key=failed_attempts.get)
    print("\n[5] Top Attacker:")
    print(f"  {top_ip} with {failed_attempts[top_ip]} failed attempts")

print("\n==============================")
print("        END OF REPORT")
print("==============================")

# ---------------- SAVE REPORT ----------------
if save_report:
    with open("report.txt", "w") as report:
        report.write("LOG ANALYSIS REPORT\n\n")

        report.write("Failed Attempts:\n")
        for ip, count in failed_attempts.items():
            if count >= 2:
                report.write(f"{ip}: {count}\n")

        report.write("\nSeverity Analysis:\n")
        for ip, count in failed_attempts.items():
            if count >= THRESHOLD:
                report.write(f"{ip}: HIGH ({count})\n")
            elif count >= 5:
                report.write(f"{ip}: MEDIUM ({count})\n")
            elif count >= 3:
                report.write(f"{ip}: LOW ({count})\n")

        report.write("\nSuccess After Failures:\n")
        for ip in set(attack_after_success):
            report.write(f"{ip}\n")

        report.write(f"\nTop Attacker: {top_ip}")

    print("\nReport saved as report.txt")