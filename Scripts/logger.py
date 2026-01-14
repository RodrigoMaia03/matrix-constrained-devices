import serial
import time
import csv
import argparse

BAUD_RATE = 115200

def log_serial(port, output_file, duration_minutes):
    print(f"Conectando na porta {port}...")
    try:
        ser = serial.Serial(port, BAUD_RATE, timeout=1)
        time.sleep(2) # Espera o ESP32 reiniciar
    except Exception as e:
        print(f"Erro ao abrir porta serial: {e}")
        return

    end_time = time.time() + (duration_minutes * 60)
    
    print(f"Iniciando gravação em {output_file} por {duration_minutes} minutos...")
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp_Host", "RTT_us"]) # Cabeçalho
        
        while time.time() < end_time:
            if ser.in_waiting > 0:
                try:
                    line = ser.readline().decode('utf-8').strip()
                    # Verifica se é um número (RTT) ou texto de debug
                    if line.isdigit():
                        writer.writerow([time.time(), line])
                        print(f"RTT: {line} us")
                    else:
                        print(f"[DEBUG ESP32]: {line}")
                except:
                    pass
    
    ser.close()
    print("Teste finalizado!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=str, required=True, help="Porta COM (ex: COM3)")
    parser.add_argument("--name", type=str, required=True, help="Nome do arquivo de saída")
    parser.add_argument("--minutes", type=int, default=10, help="Duração")
    args = parser.parse_args()

    log_serial(args.port, f"{args.name}_rtt.csv", args.minutes)