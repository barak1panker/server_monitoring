import psutil

# שימוש במעבד
print(psutil.cpu_percent(interval=1))

# שימוש בזיכרון
mem = psutil.virtual_memory()
print(f"Memory used: {mem.percent}%")

# מידע על דיסק
disk = psutil.disk_usage('/')
print(f"Disk usage: {disk.percent}%")

# תעבורת רשת

