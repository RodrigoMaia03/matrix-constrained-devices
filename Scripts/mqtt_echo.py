import paho.mqtt.client as mqtt

# Configurações
BROKER = "localhost"
PORT = 1883
TOPIC_REQ = "tcc/request"
TOPIC_RES = "tcc/response"

def on_connect(client, userdata, flags, rc):
    print(f"Echo Server Conectado! (RC: {rc})")
    client.subscribe(TOPIC_REQ)

def on_message(client, userdata, msg):
    # Assim que recebe no 'request', publica no 'response'
    client.publish(TOPIC_RES, msg.payload)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

print("Iniciando Echo Server MQTT...")
client.connect(BROKER, PORT, 60)
client.loop_forever()