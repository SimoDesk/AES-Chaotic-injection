import matplotlib.pyplot as plt
import numpy as np

def plot_hamming_weight_analysis(attack_df):
    print("\n[*] Generazione Grafico: Analisi di Potenza (Hamming Weight)...")
    
    # Prendiamo il primo pacchetto di attacco come esempio
    pkt_hw_p1 = [attack_df.loc[0, f'HW_P1_{i}'] for i in range(16)]
    pkt_hw_p2 = [attack_df.loc[0, f'HW_P2_{i}'] for i in range(16)]
    
    plt.figure(figsize=(10, 5))
    plt.plot(range(16), pkt_hw_p1 , marker='o', linestyle='-', color='b', label='Hamming Weight (Round 1)')
    plt.plot(range(16), pkt_hw_p2, marker='s', linestyle='--', color='orange', label='Hamming Weight (Round 2)')
    
    plt.title("Analisi del Peso di Hamming per Indice di Byte (Pacchetto #1)")
    plt.xlabel("Indice del Byte nello Stato AES (0-15)")
    plt.ylabel("Peso di Hamming (Numero di bit a '1')")
    plt.xticks(range(16))
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    
    plt.savefig("hamming_weight_analysis.png", dpi=300)
    plt.close()
    print("[+] Salvato: hamming_weight_analysis.png")

def plot_final_key_scores(key_scores, byte_idx):
    print(f"\n[*] Generazione Grafico: Punteggi Finali MLE Chiave (Byte {byte_idx})...")
    
    # I punteggi MLE (somma di logaritmi) sono numeri molto negativi.
    # Per visualizzarli come un classico grafico a barre dal basso verso l'alto,
    # trasliamo i valori in positivo sottraendo il punteggio più basso (il peggiore).
    visual_scores = key_scores - np.min(key_scores)
    
    best_guess = np.argmax(visual_scores)
    max_score = np.max(visual_scores)
    
    plt.figure(figsize=(10, 5))
    bars = plt.bar(range(256), visual_scores, color='steelblue', width=1.0, edgecolor='none')
    
    # Evidenziamo la chiave vincente in verde brillante
    bars[best_guess].set_color('limegreen')
    
    # Riquadro informativo con la chiave trovata
    testo_info = f"Byte di Chiave Estratto: 0x{best_guess:02x}"
    props_riquadro = dict(boxstyle='round', facecolor='whitesmoke', alpha=0.9, edgecolor='gray')
    
    plt.gca().text(0.98, 0.95, testo_info, transform=plt.gca().transAxes, fontsize=11,
                   verticalalignment='top', horizontalalignment='right', bbox=props_riquadro)
    
    plt.title(f"Distribuzione Cumulativa dei Punteggi per la Master Key (Byte {byte_idx}, MLE su 50 pacchetti)")
    plt.xlabel("Ipotesi di Byte della Chiave (0-255)")
    plt.ylabel("Punteggio Relativo (Log-Likelihood Traslata)")
    plt.xlim(-1, 256)
    
    # Aumentiamo il limite Y per non sovrapporre la barra al testo
    plt.ylim(0, max_score * 1.15)
    
    plt.grid(True, linestyle=':', alpha=0.5)
    plt.tight_layout()
    
    plt.savefig(f"mle_final_key_scores_byte_{byte_idx}.png", dpi=300)
    plt.close()
    print(f"[+] Salvato: mle_final_key_scores_byte_{byte_idx}.png")