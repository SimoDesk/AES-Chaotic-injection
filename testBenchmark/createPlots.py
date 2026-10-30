import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

OUTPUT_DIR = "plots"

def create_plots(fileName = "results.csv"):
    # Set the theme for seaborn plots and update font sizes for better readability
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 12, 'axes.titlesize': 14})

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Read the results.csv file into a DataFrame and create a new column 'Map_Short' for shorter map names
    try:
        df = pd.read_csv(fileName)
        df['Map_Short'] = df['Map'].str.replace('AES-GCM ', '').str.replace(' Map', '')
    except FileNotFoundError:
        print("Errore: file " + fileName + " non trovato.")
        exit()

    df_enc = df[df['Fase'] == 'Encryption'].copy()

    # Filter the DataFrame to only include rows where 'Fase' is either 'Encryption' or 'Decryption'
    baseline_enc = df[(df['Map'] == 'AES-GCM standard') & (df['Fase'] == 'Encryption')]
    baseline_dec = df[(df['Map'] == 'AES-GCM standard') & (df['Fase'] == 'Decryption')]

    # Retrieve baseline values for average time and energy consumption for both encryption and decryption phases
    time_enc_base = baseline_enc['Average_Time_s'].values[0] if not baseline_enc.empty else None
    time_dec_base = baseline_dec['Average_Time_s'].values[0] if not baseline_dec.empty else None

    throughput_enc_base = baseline_enc['Throughput_MB_s'].values[0] if not baseline_enc.empty else None
    throughput_dec_base = baseline_dec['Throughput_MB_s'].values[0] if not baseline_dec.empty else None


    # ---------------------------------------------------------
    # 1. Bar Plot: Average Time for Encryption and Decryption
    # ---------------------------------------------------------
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df, x='Map_Short', y='Average_Time_s', hue='Fase', palette=['#1f77b4', '#ff7f0e'])

    if time_enc_base:
        plt.axhline(y=time_enc_base, color='#1f77b4', linestyle='--', alpha=0.8, label='Baseline Encryption')
    if time_dec_base:
        plt.axhline(y=time_dec_base, color='#ff7f0e', linestyle='--', alpha=0.8, label='Baseline Decryption')

    plt.title('Average Time for Encryption and Decryption Phases')
    plt.xlabel('Algorithm')
    plt.ylabel('Average Time (s)')
    plt.xticks(rotation=45, ha='right')

    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.40), ncol=2)
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/Time.png', dpi=300, bbox_inches='tight')
    plt.close()

    # ---------------------------------------------------------
    # 1.2. Bar Plot: Average Throughput for Encryption and Decryption
    # ---------------------------------------------------------
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df, x='Map_Short', y='Throughput_MB_s', hue='Fase', palette=['#32aaff', '#ff9f4b'])

    if throughput_enc_base:
        plt.axhline(y=throughput_enc_base, color="#32aaff", linestyle='--', alpha=0.8, label='Baseline Encryption')
    if throughput_dec_base:
        plt.axhline(y=throughput_dec_base, color="#ff9f4b", linestyle='--', alpha=0.8, label='Baseline Decryption')

    plt.title('Average Throughput for Encryption and Decryption Phases')
    plt.xlabel('Algorithm')
    plt.ylabel('Throughput (MB/s)')
    plt.xticks(rotation=45, ha='right')

    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.40), ncol=2)
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/Throughput.png', dpi=300, bbox_inches='tight')
    plt.close()


    # ---------------------------------------------------------
    # 2A. Bar Plot: Average Energy Consumption for Encryption and Decryption
    # ---------------------------------------------------------
    df['Energy_J'] = df['Energy_uJ'] / 1e6
    baseline_enc_J = baseline_enc['Energy_uJ'].values[0] / 1e6 if not baseline_enc.empty else None
    baseline_dec_J = baseline_dec['Energy_uJ'].values[0] / 1e6 if not baseline_dec.empty else None

    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df, x='Map_Short', y='Energy_J', hue='Fase', palette=['#1f77b4', '#ff7f0e'], alpha=0.8)

    if baseline_enc_J:
        plt.axhline(y=baseline_enc_J, color='#1f77b4', linestyle='--', alpha=0.8, label='Encryprion energy Baseline')
    if baseline_dec_J:
        plt.axhline(y=baseline_dec_J, color='#ff7f0e', linestyle='--', alpha=0.8, label='Decryption energy Baseline')

    plt.title('Average Energy Consumption for Encryption and Decryption Phases')
    plt.xlabel('Algorithm')
    plt.ylabel('Energy (J)')
    plt.xticks(rotation=45, ha='right')

    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.40), ncol=2)
    plt.subplots_adjust(bottom=0.35)
    plt.savefig(f'{OUTPUT_DIR}/Energy.png', dpi=300, bbox_inches='tight')
    plt.close()


    # ---------------------------------------------------------
    # 2B. Line Plot: Average Power Consumption for Encryption and Decryption
    # ---------------------------------------------------------
    plt.figure(figsize=(12, 6))
    
    sns.lineplot(data=df[df['Fase'] == 'Encryption'], x='Map_Short', y='Power_W', marker='o', color='tab:red', linewidth=2, markersize=8, label='Encryption Power consumption')
    sns.lineplot(data=df[df['Fase'] == 'Decryption'], x='Map_Short', y='Power_W', marker='s', color='darkred', linestyle='--', linewidth=2, markersize=8, label='Decryption Power consumption')

    plt.title('Average Power Consumption for Encryption and Decryption Phases')
    plt.xlabel('Algorithm')
    plt.ylabel('Power (W)')
    plt.xticks(rotation=45, ha='right')

    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.40), ncol=2)
    plt.subplots_adjust(bottom=0.35)
    plt.savefig(f'{OUTPUT_DIR}/Power.png', dpi=300, bbox_inches='tight')
    plt.close()


    # ---------------------------------------------------------
    # 3. Bar Plot: Memory Footprint (Stack + Heap)
    # ---------------------------------------------------------
    df_mem = df_enc[['Map_Short', 'StackUsage_B', 'HeapUsage_B']].drop_duplicates()
    df_mem.set_index('Map_Short', inplace=True)

    ax = df_mem.plot(kind='bar', stacked=True, figsize=(10, 6), color=['#2ca02c', '#9467bd'])
    plt.title('Memory Footprint (Stack + Heap) for Encryption and Decryption Phases')
    plt.xlabel('Algorithm')
    plt.ylabel('Memory Usage (Bytes)')
    plt.xticks(rotation=45, ha='right')

    plt.legend(['Stack Usage (B)', 'Heap Usage (B)'], loc='upper center', bbox_to_anchor=(0.5, -0.30), ncol=2)
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/Memory_Footprint.png', dpi=300, bbox_inches='tight')
    plt.close()


    # ---------------------------------------------------------
    # 4. Scatter Plot: Bit Entropy of Ciphertext
    # ---------------------------------------------------------
    if 'Bit_Entropy' in df.columns:
        plt.figure(figsize=(10, 5))
        ax = sns.scatterplot(data=df_enc, x='Map_Short', y='Bit_Entropy', color='purple', s=100, zorder=5, label='Bit Entropy')
        plt.axhline(y=8.0, color='red', linestyle='--', label='Ideal Entropy (8.0 bit/byte)', zorder=4)
        
        ax.get_yaxis().get_major_formatter().set_useOffset(False)
        
        plt.ylim(7.995, 8.005)
        
        plt.title('Bit Entropy of Ciphertext for Encryption Phase')
        plt.xlabel('Algorithm')
        plt.ylabel('Bit Entropy (bit/byte)')
        plt.xticks(rotation=45, ha='right')
        
        # Legenda in basso
        plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.60), ncol=2)
        plt.subplots_adjust(bottom=0.3)
        
        plt.savefig(f'{OUTPUT_DIR}/Bit_Entropy.png', dpi=300)
        plt.close()


if __name__ == "__main__":
    create_plots()