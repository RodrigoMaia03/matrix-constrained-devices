/*
 * CENÁRIO CoAP (COM MEDIÇÃO DE RTT)
 * Biblioteca: CoAP simple
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <coap-simple.h>

#define PAYLOAD_SIZE  256
#define FREQ_HZ       5
  
const char* ssid = "ABS_2.4G";
const char* password = "PASSWORD123";
IPAddress gateway_ip(192, 168, 1, 8);

WiFiUDP udp;
Coap coap(udp);

// Variáveis de Tempo e Dados
unsigned long interval = 1000 / FREQ_HZ;
unsigned long lastSend = 0;
unsigned long sendTimeMicros = 0;
String payloadFixo;

String gerarPayload(int size) {
  String s = "";
  s += "{\"d\":\"";
  while (s.length() < size - 2) {
    s += "x";
  }
  s += "\"}";
  return s;
}

// Callback: Executado quando chega o ACK do Gateway
void callback_response(CoapPacket &packet, IPAddress ip, int port) {
  unsigned long receiveTime = micros();
  
  // Calcula o RTT
  unsigned long rtt = receiveTime - sendTimeMicros;
  
  // Imprime RTT em microsegundos
  Serial.println(rtt);
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  Serial.println("\nWiFi Conectado!");
  
  // Gera o payload fixo
  payloadFixo = gerarPayload(PAYLOAD_SIZE);
  
  // Registra callback e inicia
  coap.response(callback_response);
  coap.start();
  
  Serial.println("--- INICIO DO TESTE COAP ---");
  Serial.println("RTT_micros");
}

void loop() {
  coap.loop();

  unsigned long now = millis();
  
  if (now - lastSend >= interval) {
    lastSend = now;
    
    // Marca hora
    sendTimeMicros = micros();
    
    // Envia PUT Confirmável
    // O Gateway Python espera no recurso "send"
    coap.put(gateway_ip, 5683, "send", payloadFixo.c_str());
  }
}
