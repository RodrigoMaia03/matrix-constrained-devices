/*
   CENÁRIO MQTT (COM MEDIÇÃO DE RTT)
   Biblioteca: PubSubClient
*/

#include <WiFi.h>
#include <PubSubClient.h>

#define PAYLOAD_SIZE  256
#define FREQ_HZ       5

const char* ssid        = "ABS_2.4G";
const char* password    = "PASSWORD123";
const char* mqtt_server = "192.168.1.8";

// Tópicos para o teste de Echo
const char* topic_req   = "tcc/request";
const char* topic_res   = "tcc/response";

WiFiClient espClient;
PubSubClient client(espClient);

// Variáveis de Tempo e Dados
unsigned long interval = 1000 / FREQ_HZ;
unsigned long lastSend = 0;
unsigned long sendTimeMicros = 0;
String payloadFixo;

// Função auxiliar para gerar payload de tamanho específico
String gerarPayload(int size) {
  String s = "";
  // Cria um JSON falso para simular dado real, preenchendo com 'x' até o tamanho
  s += "{\"d\":\"";
  while (s.length() < size - 2) { // -2 para fechar o JSON "}
    s += "x";
  }
  s += "\"}";
  return s;
}

void setup_wifi() {
  delay(10);
  Serial.print("Conectando WiFi: ");
  Serial.println(ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi Conectado!");
}

// Callback: Executado quando chega a resposta (ECHO) do Gateway
void callback(char* topic, byte* message, unsigned int length) {
  unsigned long receiveTime = micros();

  // Calcula o RTT (Tempo de Ida e Volta)
  unsigned long rtt = receiveTime - sendTimeMicros;

  // Imprime formato CSV: Tempo_Ms, RTT_Us, Bytes
  // Serial.print(millis());
  // Serial.print(",");
  Serial.println(rtt); // Imprime apenas o RTT em microsegundos para facilitar a coleta
}

void reconnect() {
  while (!client.connected()) {
    String clientId = "ESP32-Test-" + String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      // Assim que conectar, assina o tópico de resposta
      client.subscribe(topic_res);
    } else {
      delay(2000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback); // Registra a função de resposta
  client.setBufferSize(512); // Aumenta o limite para aceitar payloads grandes

  // Gera o payload fixo una para não gastar CPU no loop
  payloadFixo = gerarPayload(PAYLOAD_SIZE);

  Serial.println("--- INICIO DO TESTE MQTT ---");
  Serial.print("Payload: "); Serial.print(PAYLOAD_SIZE);
  Serial.print(" bytes | Freq: "); Serial.print(FREQ_HZ); Serial.println(" Hz");
  Serial.println("RTT_micros"); // Cabeçalho do CSV
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  unsigned long now = millis();

  if (now - lastSend >= interval) {
    lastSend = now;

    // Marca hora exata do envio (microsegundos)
    sendTimeMicros = micros();

    // Envia a mensagem
    client.publish(topic_req, payloadFixo.c_str());
  }
}
