import matplotlib.pyplot as plt
import numpy as np

PLOT_FLODER = "plots/"

# Plot the Hamming weight analysis for the first packet in the attack dataset, showing the Hamming weights for both rounds of AES-GCM encryption.
def plot_hamming_weight_analysis(attack_df):
    
    # Extract the Hamming weights for the first packet (index 0) for both rounds of AES-GCM encryption. 
    # Each round has 16 bytes, so we create two lists of Hamming weights, one for each round.
    pkt_hw_p1 = [attack_df.loc[0, f'HW_P1_{i}'] for i in range(16)]
    pkt_hw_p2 = [attack_df.loc[0, f'HW_P2_{i}'] for i in range(16)]
    
    plt.figure(figsize=(10, 5))
    plt.plot(range(16), pkt_hw_p1 , marker='o', linestyle='-', color='b', label='Hamming Weight (Round 1)')
    plt.plot(range(16), pkt_hw_p2, marker='s', linestyle='--', color='orange', label='Hamming Weight (Round 2)')
    
    plt.title("Hamming Weight Analysis in the Attack Dataset (sample packet #0)", fontsize=16)
    plt.xlabel("Byte Index (0-15)")
    plt.ylabel("Hamming Weight")
    plt.xticks(range(16))
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    
    plt.savefig(f"{PLOT_FLODER}hamming_weight_analysis.png", dpi=300)

    plt.close()


# Plot the final key scores for each of the first 12 bytes of the AES key, showing the distribution of scores for each possible byte value (0-255)
# and highlighting the best guess and the real key byte if provided.
def plot_all_final_key_scores(all_key_scores, real_key_hex = None):
    
    fig, axes = plt.subplots(nrows=4, ncols=3, figsize=(18, 16))
    fig.suptitle("Confidence Scores for the First 12 Bytes of the AES Key (Random Forest Predictions)", fontsize=18, fontweight='bold')
    
    for byte_idx in range(12):
        row = byte_idx // 3
        column = byte_idx % 3

        ax = axes[row, column]
        
        key_scores = all_key_scores[byte_idx]
        visual_scores = key_scores - np.min(key_scores)
        best_guess = np.argmax(visual_scores)
        max_score = np.max(visual_scores)
        
        bars = ax.bar(range(256), visual_scores, color='steelblue', width=1.0, edgecolor='none')

        # Highlight the bar corresponding to the best guess in lime green to indicate the model's prediction for this byte.
        bars[best_guess].set_color('limegreen')
        
        info = f"Selected by the model: 0x{best_guess:02x}"
        
        # If the real key is provided, we extract the corresponding byte and compare it with the best guess. 
        # If they don't match, we color the real key's bar in red to indicate an error.
        if real_key_hex:
            real_byte = int(real_key_hex[byte_idx*2 : byte_idx*2+2], 16)

            # If the best guess does not match the real byte, we color the bar corresponding to the real byte in red to indicate an error.
            if best_guess != real_byte:
                bars[real_byte].set_color('red')
                info += f"\nReale: 0x{real_byte:02x} [ERR]"
            else:
                info += " [OK]"
        
        box = dict(boxstyle='round', facecolor='whitesmoke', alpha=0.9, edgecolor='gray')
        ax.text(0.95, 0.90, info, transform=ax.transAxes, fontsize=12,
                verticalalignment='top', horizontalalignment='right', bbox=box)
        
        ax.set_title(f"Byte {byte_idx}", fontsize=14, fontweight='bold')
        ax.set_xlim(-1, 256)
        ax.set_ylim(0, max_score * 1.25)
        ax.grid(True, linestyle=':', alpha=0.5)
        
        if column == 0:
            ax.set_ylabel("Score (Log-Likelihood)")
        if row == 3:
            ax.set_xlabel("Hypothesis Byte Value (0-255)")
            
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    
    plt.savefig(f"{PLOT_FLODER}mle_final_key_scores_all_12_bytes.png", dpi=300)

    plt.close()


# Plot the predicted probabilities for each possible byte value (0-255) for a specific byte index and packet index, highlighting the best guess and its probability.
# This plot helps justify the need for the Maximum Likelihood Estimation (MLE) approach, as it shows that the predicted probabilities for the correct byte value may not be the highest,
# and the MLE approach is needed to accumulate evidence across multiple attack samples to make a more accurate prediction of the key byte.
def plot_ml_probabilities(models, probabilities, byte_idx, pkt_idx = 0):
    
    # Get the full probability array for all 256 possible byte values, initializing it with zeros.
    full_prob_array = np.zeros(256)
    model_classes = models[byte_idx].classes_
    
    # Depending on the structure of the probabilities input, we extract the probability array for the specified byte index and packet index.
    if isinstance(probabilities, dict) or len(probabilities) > 1:
        prob_array = probabilities[byte_idx][pkt_idx]
    else:
        prob_array = probabilities[0][pkt_idx]
    
    for c_val, p_val in zip(model_classes, prob_array):
        full_prob_array[c_val] = p_val
        
    max_prob = np.max(full_prob_array)
    best_guess = np.argmax(full_prob_array)
    
    plt.figure(figsize=(10, 5))
    bars = plt.bar(range(256), full_prob_array, color='purple', width=1.0, edgecolor='none')
    
    # Highlight the bar corresponding to the best guess in lime green to indicate the model's prediction for this byte.
    if max_prob > 0:
        bars[best_guess].set_color('limegreen')
        
    box = f"Best model hypothesis: 0x{best_guess:02x} (Prob: {max_prob:.2%})"
    
    props_riquadro = dict(boxstyle='round', facecolor='whitesmoke', alpha=0.9, edgecolor='gray')
    
    plt.gca().text(0.98, 0.95, box, transform=plt.gca().transAxes, fontsize=11,
                   verticalalignment='top', horizontalalignment='right', bbox=props_riquadro)
    
    plt.title(f"Predicted Probabilities for Byte {byte_idx} (Sample Packet #{pkt_idx}, byte {byte_idx})", fontsize=16, fontweight='bold')
    plt.xlabel("S-box Output Byte Value (0-255)")
    plt.ylabel("Predicted Probability")
    plt.xlim(-1, 256)
    
    plt.ylim(0, max_prob * 1.15)
    
    plt.grid(True, linestyle=':', alpha=0.5)
    plt.tight_layout()
    
    plt.savefig(f"{PLOT_FLODER}ml_probabilities_byte_{byte_idx}.png", dpi=300)

    plt.close()