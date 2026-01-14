# Repositório do Trabalho de Conclusão de Curso - CoMatrix

Este repositório contém os componentes utilizados para a elaboração do trabalho de conclusão de curso em Engenharia de Computação, intitulado "Utilizando o Protocolo Matrix para Ecossitemas IoT com Recursos Restritos".

O trabalho foi produzido por Rodrigo da Silva Carvalho Maia, com orientação do Professor Dr. Paulo Antonio Leal Rêgo.

Este repositório serve como base para a validação da arquitetura e integrações propostas no TCC, utilizando como ponto de partida o projeto **CoMatrix**, que implementa um gateway para integração de dispositivos CoAP com a rede Matrix.

- **Repositório Original do CoMatrix (GitLab):** [https://gitlab.com/comatrix/comatrix/-/tree/master/Gateway](https://gitlab.com/comatrix/comatrix/-/tree/master/Gateway)
- **Material do Projeto CoMatrix (netidee.at):** [https://www.netidee.at/comatrix](https://www.netidee.at/comatrix)

## Estrutura do Repositório

O repositório está organizado da seguinte forma:

- **Broker/**: Contém o arquivo de configuração do broker Mosquitto (`mosquitto.conf`).
- **Firmwares ESP32/**: Contém os firmwares desenvolvidos para o microcontrolador ESP32, para os protocolos CoAP (`firmware_coap.ino`) e MQTT (`firmware_mqtt.ino`).
- **Gateway/**: Contém a implementação do gateway CoMatrix em Python (`comatrix_gateway.py`), o arquivo de configuração do homeserver Synapse (`homeserver.yaml`) e um arquivo de dependências (`requirements.txt`).
- **Resources/**: Contém o arquivo `RESUMO_FINAL_TCC.csv` com um resumo dos resultados obtidos.
- **Scripts/**: Contém diversos scripts utilizados para automação de tarefas, como autenticação na rede Matrix (`autentication_matrix_bash.sh`, `autentication_matrix_shell.ps1`), logging de dados (`logger.py`), monitoramento de containers Docker (`monitor_docker.py`), um cliente de echo MQTT (`mqtt_echo.py`) e processamento de dados (`processar_dados.py`).

## Executando os Servidores

Para executar os servidores Synapse e Mosquitto, utilize os seguintes comandos Docker:

**Synapse:**
```bash
docker run -d --name synapse -p 8008:8008 -v ${PWD}:/data matrixdotorg/synapse:latest
```

**Mosquitto:**
```bash
docker run -it -p 1883:1883 -v ${PWD}/mosquitto.conf:/mosquitto/config/mosquitto.conf eclipse-mosquitto
```

## Dependências

Para executar os scripts Python presentes na pasta `Scripts`, é necessário instalar as seguintes bibliotecas:

```bash
pip install -r requirements.txt
```
