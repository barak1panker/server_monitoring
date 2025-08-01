import psycopg2

conn = psycopg2.connect(
    dbname='monitor-info',     
    user='postgres',   
    password='',  
    host='localhost',
    port='5432'
)

cur = conn.cursor()


device_name = "Device-A"
description = "main server"

cur.execute("""
    INSERT INTO devices (device_name, description)
    VALUES (%s, %s)
    RETURNING id;
""", (device_name, description))

device_id = cur.fetchone()[0]  
print("ID :", device_id)

conn.commit()
cur.close()
conn.close()