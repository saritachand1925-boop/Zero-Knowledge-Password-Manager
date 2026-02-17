import mysql.connector

conn = mysql.connector.connect(
    host="switchyard.proxy.rlwy.net",
    port=51013,
    user="root",
    password="PSYCbLbIcbFldPKnlYOFJhJPoBTxJFPt",
    database="ciphersphere"
)
print("Connected successfully!")
conn.close()
