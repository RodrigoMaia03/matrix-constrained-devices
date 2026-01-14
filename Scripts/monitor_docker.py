import subprocess
import time
import csv
import argparse
import re

def parse_memory(mem_str):
    """Converte strings como '1.5MiB' ou '500KiB' para Megabytes (float)"""
    try:
        value_str = mem_str.split(' / ')[0].strip()
        
        # Remove caracteres não numéricos exceto ponto
        num_str = re.sub(r'[a-zA-Z]', '', value_str)
        val = float(num_str)
        
        if "GiB" in value_str:
            return val * 1024
        elif "MiB" in value_str:
            return val
        elif "KiB" in value_str:
            return val / 1024
        elif "B" in value_str:
            return val / (1024*1024)
        return val
    except:
        return 0.0

def monitor_docker(container_name, duration, output_file):
    print(f"Iniciando monitoramento do Container '{container_name}' por {duration} segundos...")
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Time_Sec", "CPU_Percent", "Memory_MB"])
        
        start_time = time.time()
        
        for i in range(duration):
            try:
                # Chama o comando 'docker stats' para pegar apenas CPU e Memória
                result = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}};{{.MemUsage}}", container_name],
                    capture_output=True, text=True
                )
                
                output = result.stdout.strip()
                if output:
                    parts = output.split(';')
                    if len(parts) == 2:
                        cpu_raw = parts[0].replace('%', '')
                        mem_raw = parts[1]
                        
                        cpu_val = float(cpu_raw)
                        mem_val = parse_memory(mem_raw)
                        
                        writer.writerow([i+1, cpu_val, f"{mem_val:.2f}"])
                        print(f"Sec {i+1}: CPU {cpu_val}% | Mem {mem_val:.2f}MB")
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Erro na leitura: {e}")
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", type=str, required=True, help="Nome ou ID do Container")
    parser.add_argument("--name", type=str, required=True, help="Nome do arquivo de saída")
    parser.add_argument("--minutes", type=int, default=10, help="Duração em minutos")
    args = parser.parse_args()

    monitor_docker(args.container, args.minutes * 60, f"{args.name}_resources.csv")