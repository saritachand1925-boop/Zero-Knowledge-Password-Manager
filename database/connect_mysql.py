import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
        port=3306,
        user="root",
        password="puja2059",
        database="ciphersphere"
)
print("Connected successfully!")
conn.close()
