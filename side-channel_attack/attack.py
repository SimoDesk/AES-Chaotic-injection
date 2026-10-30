import subprocess
import sys
import os
import argparse

import pandas as pd
import numpy as np

import struct

from sklearn.ensemble import RandomForestClassifier

import createPlots as plotMaker

TRAINING_CSV = "data/training_data.csv"

ATTACK_CSV = "data/attack_data.csv"

# Officially known S-Box for AES, used for the key recovery phase
sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]
inv_sbox = {v: k for k, v in enumerate(sbox)}

# TRAINING PHASE 
# Train Random Forest models for a specific number of bytes (byteNumber) using the training data (train_df) for a given attack phase (attackPhase).
def trainModels(train_df, byteNumber, attackPhase):
    models = []

    for byte_idx in range(byteNumber):
        # X_train contains the Hamming weights for the current byte as a matrix of shape (8000, 1) due to the needs of the RandomForestClassifier which expects a 2D array for features.
        # This matrix conteins the Hamming weights of the current byte for all 8000 profiling samples and those are used to train the Random Forest model to predict the target byte value based on the Hamming weight.
        X_train = train_df[[f'HW_P{attackPhase}_{byte_idx}']].values

        # y_train contains the target byte values for the current byte, which are the actual byte values of the AES key for all 8000 profiling samples. 
        # These values are the "results" that the Random Forest model will use to learn the relationship between the Hamming weights and the actual byte values.
        y_train = train_df[f'Target_P{attackPhase}_{byte_idx}'].values

        # Set up the Random Forest Classifier with specific hyperparameters.
        # The parameters are chosen to balance the model's complexity and its ability to generalize from the training data:
        # n_estimators = 100: The number of trees in the forest. More trees can improve the prediction accuracy but also increase computation time, 100 is a common choice for a good balance.
        # max_depth = 8: The maximum depth of each tree. Limiting the depth helps prevent overfitting, ensuring that the model captures the underlying patterns without memorizing the training data.
        # min_samples_leaf = 10: The minimum number of samples required to be at a leaf node. This parameter helps to smooth the model, making it less sensitive to noise in the training data.
        # min_samples_split = 20: The minimum number of samples required to split an internal node. This parameter also helps to prevent overfitting by ensuring that nodes are only split when there is enough data to make a reliable decision.
        # random_state = 111: A seed for the random number generator, ensuring that the results are reproducible. Using a fixed random state allows for consistent results across different runs of the code.
        # n_jobs = 8: The number of jobs to run in parallel on different cores of the CPU. This speeds up the training process by utilizing multiple cores, making the training faster, especially with a large number of trees.
        rf = RandomForestClassifier(n_estimators = 100, max_depth = 8, min_samples_leaf = 10, min_samples_split = 20, random_state = 111, n_jobs = 8)

        # Train the Random Forest model on the training data (Hamming weights and target byte values) by making each tree in the forest learn to predict the target byte value based on the Hamming weight of the current byte.
        # then every tree in the forest will vote on the predicted class for each sample, and the class with the most votes will be the final prediction for that sample.
        rf.fit(X_train, y_train)

        models.append(rf)

    return models

# The function used in the MixColumn operation takes a byte (8 bits) as input and returns the result of multiplying that byte by 2 in GF(2^8).
# In order to perform this multiplication as quickly as possible, we use a bitwise left shift operation to multiply the byte by 2, ((x << 1) & 0xFF) adding a bitwise AND operation with 0xFF to ensure that the result is still a byte (8 bits).
# Then we check if the most significant bit (MSB) of the original byte is set (i.e., if x >= 128). If it is, we perform a bitwise XOR operation with 0x1B, which is the irreducible polynomial used in AES to reduce the result back into GF(2^8).
def galoisDouble(x):
    return ((x << 1) & 0xFF) ^ ((x >> 7) * 0x1B)


# aesColumnSimulation function simulates the first round of AES for a specific column col.
# Given the public initialization vector (IV) and a first half key hypothesis (known_k1_12bytes + guess_k1):
# 1. Add round key (IV || 0x00000002) XOR (known_k1_12bytes || guess_k1)
# 2. Apply the S-Box to the result of the AddRoundKey operation.
# 3. Apply the MixColumns operation to the result of the S-Box operation.
# The output of this function is the result of the MixColumns operation, which will be used as input for the second round of AES.
def aseColumnSimulation(IV, known_k1_12bytes, guess_k1, col):

    # Considering an AES block of 16 bytes, before the ShiftRows operation, the unknown byte of K1 are in the forth column of the AES state, which holds the indices 12, 13, 14, and 15.
    # So, for each column of AES, the unknown byte of K1 is at index 15 - the current column index.
    unknown_k1_idx = 15 - col

    # shift_rows_map is a dictionary that defines the column where each unknown byte of K1 is located in the AES state after the ShiftRows operation.
    shift_rows_map = {
        0: [0, 5, 10, 15], 1: [4, 9, 14, 3], 2: [8, 13, 2, 7], 3: [12, 1, 6, 11]
    }

    # By using the shift_rows_map, we can determine which bytes of IV Xor K1 will be used as input for the MixColumns operation.
    involved_idxs = shift_rows_map[col]

    # Following NIST recommendations for AES-GCM, since the IV is 12 bytes long (as for SATCOM standards), the last 4 bytes of the IV are fixed to 0x00000002, 
    # so they don't provide any information about the key bytes.
    input_bytes = list(IV) + [0x00, 0x00, 0x00, 0x02]
    
    # By applying the known S-box only to the bytes involved with the shift_rows_map, we can calculate at the same time the AddRoundKey and the SubBytes operations, which are the first two steps of the AES round function.
    known_bytes = [sbox[input_bytes[i] ^ known_k1_12bytes[i]] if i < 12 else 0 for i in involved_idxs]
    
    # The same calculation is done for the unknown byte of K1, but in this case we use the guess_k1 value to calculate the expected output of the S-Box for this specific guess.
    unknown_byte = sbox[input_bytes[unknown_k1_idx] ^ guess_k1]
    
    # Then we assign the known bytes and the unknown byte to form the complete column hypothesis output of AddRoundKey, SubBytes and ShiftRows operations, which will be used as input for the MixColumns operation. 
    column_hypothesis = [0, 0, 0, 0]
    for i in involved_idxs:
        if i < 12:
            column_hypothesis[i % 4] = known_bytes[involved_idxs.index(i)]
        else:
            column_hypothesis[i % 4] = unknown_byte

    h0, h1, h2, h3 = column_hypothesis
    
    # Following the implementation of the MixColumn operation which uses each byte moltiplied by 1, 2 or 3 in GF(2^8), we pre-calculate the x2 operation, since
    # the x1 operation is just the byte itself, and the x3 operation is just the x2 operation XORed with the byte itself.
    x0, x1, x2, x3 = galoisDouble(h0), galoisDouble(h1), galoisDouble(h2), galoisDouble(h3)

    # The official MixColumn operation is:
    # s'0 = (2 * s0) ^ (3 * s1) ^ (1 * s2) ^ (1 * s3)
    # s'1 = (1 * s0) ^ (2 * s1) ^ (3 * s2) ^ (1 * s3)
    # s'2 = (1 * s0) ^ (1 * s1) ^ (2 * s2) ^ (3 * s3)
    # s'3 = (3 * s0) ^ (1 * s1) ^ (1 * s2) ^ (2 * s3)
    M = [
        x0 ^ (x1 ^ h1) ^ h2 ^ h3,
        h0 ^ x1 ^ (x2 ^ h2) ^ h3,
        h0 ^ h1 ^ x2 ^ (x3 ^ h3),
        (x0 ^ h0) ^ h1 ^ h2 ^ x3
    ]

    return M

# 1st phase attack uses the trained Random Forest models to predict the first 12 bytes of the AES key based on the Hamming weights of the attack samples.
# The other 4 bytes of the key are not recovered in this phase, because of the way the last 4 bytes of AES-GCM IV are. 
# (For an IV of 12, which is standard, the last 4 bytes are fixed to 0x00000002, so they don't provide any information about the key bytes.)
def phase_1_attack():
    print("\n--- Start key extraction for the first 12 bytes of the AES key ---")

    # Load the profiling data from the CSV file into a pandas DataFrame. This data contains the Hamming weights and target byte values for training the Random Forest models.
    train_df = pd.read_csv(TRAINING_CSV)

    # Train the Random Forest models for the first 12 bytes of the AES key using the profiling data.
    models = trainModels(train_df, 12, 1)

    # Load the attack data from the CSV file into a pandas DataFrame. This data contains only the Hamming weights of the attack samples, which will be used to predict the first 12 bytes of the AES key.
    attack_df = pd.read_csv(ATTACK_CSV)

    # Plot the Hamming weight analysis for the attack samples, which provides a visual representation of an example of the training data and the attack data, 
    # showing the Hamming weights for both rounds of AES-GCM encryption for the first packet in the attack dataset.
    plotMaker.plot_hamming_weight_analysis(attack_df)

    # Initialize a list to store the recovered key bytes
    recovered_key_bytes = []

    # all_key_scores will hold the predicted scores for each possible byte value (0-255) for each of the first 12 bytes of the AES key.
    all_key_scores = []

    # For each byte of the IV (Initialization Vector), perform the training and attack phases to recover the corresponding byte of the AES key.
    for byte_idx in range(12):
        print(f"\nByte {byte_idx} under analysis...")        
        
        # Give the trained model the Hamming weights of the current byte from the attack samples to predict the probabilities of each possible byte value (0-255) for each sample.
        X_attack = attack_df[[f'HW_P1_{byte_idx}']].values

        # ML ATTACK
        # The predict_proba method returns a numpy matrix of shape (50, 256), where each row corresponds to an attack sample and each column corresponds to a possible byte value (0-255).
        # Each entry in the matrix represents the probability that the corresponding attack sample has the corresponding byte
        probabilities = models[byte_idx].predict_proba(X_attack)

        # For the first byte of the key, we generate a plot showing the predicted probabilities for each possible byte value (0-255) for the first attack sample (pkt_idx=0).
        # This plot helps justify the need of the Maximum Likelihood Estimation (MLE) approach, as it shows that the predicted probabilities for the correct byte value may not be the highest,
        # and the MLE approach is needed to accumulate evidence across multiple attack samples to make a more accurate prediction of the key byte.
        if byte_idx == 0:
            plotMaker.plot_ml_probabilities(models, [probabilities], byte_idx, pkt_idx=0)

        # After calling rf,fit inside the trainModels function, each model contains a classes_ attribute that holds the unique class labels (byte values) that the model was trained on.
        # Even if it's highly unlikely, it's possible that not all byte values (0-255) were present in the training data for a specific byte index, so the classes_ attribute may not contain all 256 possible byte values.
        # To handle this, we create a mapping from each class label (byte value) to its corresponding index in the probability array returned by predict_proba.
        prob_idx = {c: i for i, c in enumerate(models[byte_idx].classes_)}

        # Initialize an array to hold the scores for each possible key byte value (0-255). Each index in this array corresponds to a possible byte value.
        key_scores = np.zeros(256)

        # In order to accumulate the scores, for each attack sample, compute the likelihood of each possible key byte value (0-255) based on the predicted probabilities from 
        # the Random Forest model. Then sum the log probabilities for each possible byte value across all attack samples to get a final score for each possible byte value of the key.
        for pkt_idx in range(len(attack_df)):

            # Convert the IV from hexadecimal string to bytes.
            iv_hex = attack_df.loc[pkt_idx, 'IV']
            iv_bytes = bytes.fromhex(iv_hex)
            
            # Select only the byte of the IV that corresponds to the current byte index being analyzed.
            input_byte = iv_bytes[byte_idx]

            # Retrieve the predicted probabilities for the current attack sample from the probabilities array. 
            # This array contains the model's predicted probabilities for each possible byte value (0-255) for the current sample.
            prob_array = probabilities[pkt_idx]

            # For each possible key byte guess (0-255), compute the expected output of the S-Box when the input byte is XORed with the guessed key byte.
            for guess_k in range(256):

                # Calculate the output that would be expected if the guessed key byte is correct by following the standard procedure: sbox[input_byte ^ guess_k].
                expected_target = sbox[input_byte ^ guess_k]

                # If the expected output is a valid class (i.e., it was seen during training), retrieve its predicted probability from the prob_array.
                # To calculate the score for the guessed key byte a sum of log probabilities is used instead of a product to avoid numerical underflow issues that can occur when multiplying many small probabilities together.
                # moreover, a small constant (1e-9) is added to the probability to prevent taking the logarithm of zero, which is undefined.
                if expected_target in prob_idx:
                    # Retrieve the predicted probability for the expected output from the prob_array using the class_to_idx mapping to find the correct index.
                    prob = prob_array[prob_idx[expected_target]]
                    key_scores[guess_k] += np.log(prob + 1e-9)
                else:
                    key_scores[guess_k] += np.log(1e-9)
                    
        # Get the index of the maximum score in the key_scores array, which corresponds to the most likely key byte value for the current byte index.
        best_key_guess = np.argmax(key_scores)

        # Append the best key guess for the current byte index to the recovered_key_bytes list, which will hold the recovered bytes of the AES key.
        recovered_key_bytes.append(best_key_guess)

        all_key_scores.append(key_scores)

        print(f" -> Found: {hex(best_key_guess)[2:].zfill(2)}")


    # After recovering all 12 bytes of the AES key, plot the final key scores for each byte to visualize the confidence of the predictions made by the Random Forest models.
    plotMaker.plot_all_final_key_scores(all_key_scores, REAL_KEY)

    # Convert the recovered key bytes to a hexadecimal string representation, where each byte is represented as a two-character hex string, and concatenate them to form the final recovered key.
    hex_key = "".join([hex(b)[2:].zfill(2) for b in recovered_key_bytes])

    return hex_key


# For the 2nd phase the attack shifts to a more complex algebraic approach, where the first 12 bytes of the key are known and, thanks for the indipencency of the 4 columns of AES, 
# it is possible to use a divide et impera approach where for each uknown byte of K1 the ML model guess with an high degree of acuracy 4 bytes of K2, which are the key bytes used in the second round of AES.
# Following this approach, at the end of the 2nd phase, we will have 4 files, one for each column of AES, containing all the possible combinations of K1 and K2 bytes.
# By using a brute-force approach in C, it is possible to find the correct combination of K1 and K2 bytes that will allow to recover the full AES key in a 2^32 search space instead of 2^128, which is the full key space of AES.
def phase_2_attack(known_k1_12bytes):
    print("\n--- Start algebraic key recovery for all the combinations of possible keys ---")

    # Load the profiling data from the CSV file into a pandas DataFrame. This data contains the Hamming weights and target byte values for training the Random Forest models.
    train_df = pd.read_csv(TRAINING_CSV)
    
    # Train the Random Forest models for all 16 bytes of the second half of the AES key using the profiling data.
    models = trainModels(train_df, 16, 2)

    # Load the attack data from the CSV file into a pandas DataFrame. This data contains only the Hamming weights of the attack samples, which will be used to predict the second half of the AES key.
    attack_df = pd.read_csv(ATTACK_CSV)
    num_packets = len(attack_df)

    # probabilities will hold the predicted probabilities for each byte of the second half of the AES key for all attack samples.
    probabilities = {}

    # After calling rf,fit inside the trainModels function, each model contains a classes_ attribute that holds the unique class labels (byte values) that the model was trained on.
    # Even if it's highly unlikely, it's possible that not all byte values (0-255) were present in the training data for a specific byte index, so the classes_ attribute may not contain all 256 possible byte values.
    # To handle this, we create a mapping from each class label (byte value) to its corresponding index in the probability array returned by predict_proba.
    prob_idxs = {}
    
    # Trained models are used to predict the probabilities of each possible byte value (0-255) for each sample in the attack data for all 16 bytes of the second half of the AES key.
    for byte_idx in range(16):
        # Give the trained model the Hamming weights of the current byte from the attack samples to predict the probabilities of each possible byte value (0-255) for each sample.
        X_attack = attack_df[[f'HW_P2_{byte_idx}']].values

        # ML ATTACK
        # The predict_proba method returns a numpy matrix of shape (50, 256), where each row corresponds to an attack sample and each column corresponds to a possible byte value (0-255).
        # Each entry in the matrix represents the probability that the corresponding attack sample has the corresponding byte
        probabilities[byte_idx] = models[byte_idx].predict_proba(X_attack)

        prob_idxs[byte_idx] = {c: i for i, c in enumerate(models[byte_idx].classes_)}


    # k2_targets_map is a dictionary that defines the mapping of byte indices in the AES state to the corresponding target byte indices in the second half of the AES key (K2).
    k2_targets_map = {
        0: [0, 1, 2, 3], 1: [4, 5, 6, 7], 2: [8, 9, 10, 11], 3: [12, 13, 14, 15]
    }

    # Start of the divide et impera approach for each column of AES, where for each unknown byte of K1 the ML model guess with an high degree of acuracy 4 bytes of K2.
    for col in range(4):
        print(f"\n[*] Starting partial key recovery for column {col}...")

        # By using the k2_targets_map, we can determine which bytes of K2 will be used as targets for the ML model predictions.
        # This mapping is crucial for the divide et impera approach, as it allows us to focus on the relevant bytes of K2 for each unknown byte of K1.
        involved_k2_idx = k2_targets_map[col]

        # Initialize a list to hold the hypothesis for the missing byte of K1 and the corresponding best guesses for the 4 bytes of K2.
        bytes_hypotesis = []
        
        # Test all 256 possible values for the unknown byte of K1 (0-255) to find the best guesses for the corresponding 4 bytes of K2.
        for guess_k1 in range(256):
            
            # For each of the four bytes of K2 that are influenced by the current unknown byte of K1, we initialize an array to hold the scores for each possible byte value (0-255).
            # Each index in this array corresponds to a possible byte value, and the scores will be accumulated based on the predicted probabilities from the ML model for each attack sample.
            k2_scores = [np.zeros(256) for _ in range(4)]

            # In order to accumulate the scores, for each attack sample, compute the likelihood of each possible key byte value (0-255) based on the predicted probabilities from 
            # the Random Forest model. Then sum the log probabilities for each possible byte value across all attack samples to get a final score for each possible byte value of K2.
            for pkt_idx in range(num_packets):
                
                # attack_pkt is a pandas Series object that represents the current attack sample (row) in the attack DataFrame. It contains all the information for the current packet, including the IV and the Hamming weights for each byte of K1 and K2.
                attack_pkt = attack_df.iloc[pkt_idx]

                # From the current attack sample, we extract the IV (Initialization Vector) in hexadecimal format and convert it to bytes. This IV is used as part of the input for the MixColumns operation in AES.
                iv = bytes.fromhex(attack_pkt['IV'])

                # We call the aseColumnSimulation function to simulate the first round of AES for the current column (col) using the extracted IV, the known first 12 bytes of K1, and the current guess for the unknown byte of K1.
                mixed_col = aseColumnSimulation(iv, known_k1_12bytes, guess_k1, col)                
                
                # Then for each of the four bytes of K2 that are influenced by the current unknown byte of K1, we calculate the expected output of the S-Box for each possible byte value (0-255) of K2 thanks to the ML model predictions.
                for j in range(4):

                    # Retrieve the index of the current byte of K2 that is influenced by the current unknown byte of K1.
                    curr_k2 = involved_k2_idx[j]

                    # From the dictionary containing class indexes for each byte of K2, we retrieve the mapping for the current byte of K2.
                    prob_idx = prob_idxs[curr_k2]

                    # From the matrix of predicted probabilities for each byte of K2, we retrieve the array of probabilities for the current attack sample and the current byte of K2.
                    prob_array = probabilities[curr_k2][pkt_idx]

                    # For each possible key byte guess (0-255), compute the expected output of the S-Box when the input byte is XORed with the guessed byte output from the MixColumns operation.
                    for guess_k2 in range(256):

                        # Calculate the expected output that would be expected if the guessed key byte is correct by following the standard procedure: sbox[guess_k2 ^ mixed_col[j]].
                        expected_target = sbox[guess_k2 ^ mixed_col[j]]

                        # If the expected output is a valid class (i.e., it was seen during training), retrieve its predicted probability from the prob_array.
                        # To calculate the score for the guessed key byte a sum of log probabilities is used instead of a product to avoid numerical underflow issues that can occur when multiplying many small probabilities together.
                        # moreover, a small constant (1e-9) is added to the probability to prevent taking the logarithm of zero, which is undefined.
                        if expected_target in prob_idx:
                            prob = prob_array[prob_idx[expected_target]]
                            k2_scores[j][guess_k2] += np.log(prob + 1e-9)
                        else:
                            k2_scores[j][guess_k2] += np.log(1e-9)

            # After accumulating the scores for each K2 byte influenced by the current guess of K1,
            # we find the best guesses for each of the four bytes of K2 by selecting the byte value with the maximum score for each byte,
            # creating a hypothesis that combines the current guess for K1 with the best guesses for the corresponding K2 bytes.
            best_k2_0 = np.argmax(k2_scores[0])
            best_k2_1 = np.argmax(k2_scores[1])
            best_k2_2 = np.argmax(k2_scores[2])
            best_k2_3 = np.argmax(k2_scores[3])
            
            # Then we append the current guess for K1 and the best guesses for the corresponding K2 bytes to the bytes_hypotesis list, which will hold all the hypotheses for the current column of AES.
            bytes_hypotesis.append(struct.pack("5B", guess_k1, best_k2_0, best_k2_1, best_k2_2, best_k2_3))
            
        # After an hypothesis has been generated for each possible value of the current unknown byte of K1, we write the bytes_hypotesis list to a binary file named col{col}_candidates.bin, where {col} is the current column index.
        with open(f"guesses/col{col}_candidates.bin", "wb") as f:
            for item in bytes_hypotesis:
                f.write(item)
                
    print("\n[*] All hypotheses for the unknown bytes of K1 and the corresponding best guesses for K2 have been generated and saved to binary files.")


EXE_WD = "executables/"

REAL_KEY = ""

if __name__ == "__main__":
    subprocess.run(["make", "clear"], check=True)

    subprocess.run(["make"], check=True)

    # Check if the required directories for storing guesses, executables, and data exist, and create them if they do not. This ensures that the necessary directory structure is in place for the attack to run successfully.
    # This directory will be used to store the binary files containing the hypotheses for the unknown bytes of K1 and the corresponding best guesses for K2.
    if not os.path.exists("guesses"):
        os.makedirs("guesses")
    if not os.path.exists("executables"):
        os.makedirs("executables")
    if not os.path.exists("data"):
        os.makedirs("data")
    if not os.path.exists("plots"):
        os.makedirs("plots")

    # Set up command-line argument parsing to allow the user to specify the type of mapping to use for the attack and whether to run a quick check to verify the attack's success.
    parser = argparse.ArgumentParser(description="Side-channel attack on AES-GCM using Random Forest models.")
    parser.add_argument("--map", type=str, default="standard", help="Type of mapping to use for the attack (default: standard).")
    parser.add_argument("--quick", action='store_true', help="Run a quick check to verify the attack's success (default: False).")

    # Determine the type of mapping to use for the attack based on command-line arguments. 
    # The default mapping type is "standard", but it can be overridden by providing an argument when running the script.
    args = parser.parse_args()
    map_type = args.map

    res = subprocess.run([f"./{EXE_WD}create_ciphers", map_type], check=True, capture_output=True, text=True)

    # Extract the necessary variables from the output of the create_ciphers program, which include the target IV, ciphertext, AAD, tag, and the original key used for encryption.
    target_iv_hex = ""
    target_cipher_hex = ""
    target_aad_hex = ""
    target_tag_hex = ""

    for line in res.stdout.strip().splitlines():
        if line.startswith("TARGET_IV="):
            target_iv_hex = line.split("=")[1].strip()
        elif line.startswith("TARGET_CIPHER="):
            target_cipher_hex = line.split("=")[1].strip()
        elif line.startswith("TARGET_AAD="):
            target_aad_hex = line.split("=")[1].strip()
        elif line.startswith("TARGET_TAG="):
            target_tag_hex = line.split("=")[1].strip()
        elif line.startswith("KEY="):
            REAL_KEY = line.split("=")[1].strip()
        elif len(line) == 64 and "=" not in line:
            # Fallback nel caso in cui tu abbia lasciato anche il vecchio printf all'inizio
            REAL_KEY = line.strip()

    if not all([REAL_KEY, target_iv_hex, target_cipher_hex, target_aad_hex, target_tag_hex]):
        print("Error: Missing required output from create_ciphers. Please check the output format.")
        sys.exit(1)

    # Perform the first phase of the attack to recover the first 12 bytes of the AES key using the trained Random Forest models and the attack data.
    first12Found = phase_1_attack()

    if first12Found == REAL_KEY[:24]:
        print("\nSUCCESS: Found the first 12 bytes of the AES key correctly!")
        print(f"Original key : {REAL_KEY}")
        print(f"Found portion: {first12Found}")
    else:
        print("\nERROR: The first 12 bytes of the AES key were not found correctly.")
        print(f"Original key : {REAL_KEY}")
        print(f"Found portion: {first12Found}")

    # Perform the second phase of the attack to recover the remaining 4 bytes of the AES key using an algebraic approach and the hypotheses generated in the first phase.
    phase_2_attack(bytes.fromhex(first12Found))

    print("\n--- Starting brute-force search for the correct combination of K1 and K2 bytes ---")

    # If the --quick flag is provided, run a quick check to verify the success of the attack by executing the quick_check program with the found first 12 bytes of the key and the original key used for encryption.
    if args.quick:
        print("\n[*] Running quick check to verify the attack's success...")
        subprocess.run([f"./{EXE_WD}quick_check", first12Found, REAL_KEY], check=True)
        sys.exit()
    
    # If the --quick flag is not provided, run the brute_force program to search for the correct combination of K1 and K2 bytes by using the hypotheses generated in the second phase of the attack 
    # to decrypt the target ciphertext and verify if the decryption is successful by checking the tag and AAD.
    subprocess.run(
        [
            f"./{EXE_WD}brute_force", 
            first12Found, 
            map_type,
            target_iv_hex,
            target_cipher_hex,
            target_aad_hex,
            target_tag_hex
        ], 
    )
    

