file = open("web_requests.log", "r")
logs = file.readlines()

user_count = {}
ip_count = {}
error_count = 0

for line in logs:
    parts = line.strip().split(" - ")
    ip = parts[0]
    user = parts[1]
    status = int(parts[2])

    # Count users
    user_count[user] = user_count.get(user, 0) + 1

    # Count IPs
    ip_count[ip] = ip_count.get(ip, 0) + 1

    # Count errors
    if status >= 400:
        error_count += 1

# Most active user
most_active_user = max(user_count, key=user_count.get)

# Most active IP
most_active_ip = max(ip_count, key=ip_count.get)

# Print results
print("Most Active User:", most_active_user)
print("Most Active IP:", most_active_ip)
print("Total Errors:", error_count)

print("\nSuspicious Users:")
for user, count in user_count.items():
    if count > 5:
        print(user, "is suspicious")

# Save report
with open("report.txt", "w") as report:
    report.write("Log Analysis Report\n")
    report.write(f"Most Active User: {most_active_user}\n")
    report.write(f"Most Active IP: {most_active_ip}\n")
    report.write(f"Total Errors: {error_count}\n")