import pandas as pd
import glob
import os

# Tempo de warm-up em segundos
WARMUP_SECONDS = 120  # Ex: 120 para 2 minutos, 60 para 1 minuto
# --------------------

def aplicar_warmup(df, time_col, is_timestamp=False):
    """Remove as linhas correspondentes ao período de aquecimento."""
    if df.empty: return df
    
    if is_timestamp:
        start_time = df[time_col].iloc[0]
        df['Tempo_Relativo'] = df[time_col] - start_time
        filtro = df['Tempo_Relativo'] > WARMUP_SECONDS
    else:
        filtro = df[time_col] > WARMUP_SECONDS
        
    df_filtrado = df[filtro]
    
    return df_filtrado

def processar_rtt(file_path):
    try:
        df = pd.read_csv(file_path)
        if 'RTT_us' not in df.columns: return None

        if 'Timestamp_Host' in df.columns:
            df = aplicar_warmup(df, 'Timestamp_Host', is_timestamp=True)
        
        if df.empty:
            print(f"AVISO: {file_path} ficou vazio após remover warm-up!")
            return None
        
        # Converte para milissegundos
        rtt_ms = df['RTT_us'] / 1000.0
        
        return {
            'Amostras_Validas': len(df),
            'Latencia_Media_ms': rtt_ms.mean(),
            'Latencia_Min_ms': rtt_ms.min(),
            'Latencia_Max_ms': rtt_ms.max(),
            'Jitter_StdDev_ms': rtt_ms.std(),
            'P95_ms': rtt_ms.quantile(0.95),
            'P99_ms': rtt_ms.quantile(0.99)
        }
    except Exception as e:
        print(f"Erro em {file_path}: {e}")
        return None

def processar_recursos(file_path):
    try:
        df = pd.read_csv(file_path)
        col_cpu = 'CPU_Percent'
        # Detecta nome da coluna de memória
        col_ram = 'Memory_RSS_MB' if 'Memory_RSS_MB' in df.columns else 'Memory_MB'
        
        if col_cpu not in df.columns: return None
        
        if 'Time_Sec' in df.columns:
            df = aplicar_warmup(df, 'Time_Sec', is_timestamp=False)
            
        if df.empty: return None
        
        return {
            'Amostras_Validas': len(df),
            'CPU_Media': df[col_cpu].mean(),
            'CPU_Max': df[col_cpu].max(),
            'RAM_Media_MB': df[col_ram].mean(),
            'RAM_Max_MB': df[col_ram].max()
        }
    except Exception as e:
        print(f"Erro em {file_path}: {e}")
        return None

summary_data = []

print(f"Iniciando processamento (Ignorando primeiros {WARMUP_SECONDS}s)...")

# Varre todos os CSVs da pasta
for filename in glob.glob("*.csv"):
    # Pula o próprio arquivo de resumo se ele já existir
    if "RESUMO" in filename: continue

    stats = None
    tipo = ""

    if "resources" in filename:
        stats = processar_recursos(filename)
        tipo = "RECURSOS"
    elif "rtt" in filename:
        stats = processar_rtt(filename)
        tipo = "REDE"
    
    if stats:
        stats['Arquivo'] = filename
        stats['Tipo'] = tipo
        
        # Tenta extrair metadados do nome (ex: mqtt_16b_1hz)
        parts = filename.replace('.csv', '').split('_')
        
        # Lógica simples para tentar achar Protocolo, Payload e Frequência
        try:
            stats['Protocolo'] = parts[0]
            stats['Payload'] = parts[1]
            stats['Freq'] = parts[2]
        except:
            stats['Protocolo'] = "Desconhecido"

        summary_data.append(stats)

if summary_data:
    df_final = pd.DataFrame(summary_data)
    
    # Reordena colunas para facilitar leitura
    cols = ['Tipo', 'Protocolo', 'Payload', 'Freq', 'Amostras_Validas'] + [c for c in df_final.columns if c not in ['Tipo', 'Protocolo', 'Payload', 'Freq', 'Amostras_Validas', 'Arquivo']]
    df_final = df_final[cols]
    
    df_final.sort_values(by=['Tipo', 'Protocolo', 'Payload'], inplace=True)
    df_final.to_csv("RESUMO_FINAL_TCC.csv", index=False, sep=';', decimal=',', float_format='%.4f')
    print("Processamento concluído! Abra o arquivo RESUMO_FINAL_TCC.csv")
else:
    print("Nenhum arquivo CSV válido encontrado.")