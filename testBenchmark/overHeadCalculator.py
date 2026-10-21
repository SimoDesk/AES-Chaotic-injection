import pandas as pd

def calc_overhead(fileName = 'results.csv'):   

    # Read the CSV file into a DataFrame and store it in the variable dataFrame
    dataFrame = pd.read_csv(fileName)

    # Define the metrics for which the overhead will be calculated
    metrics = ['Total_Time_s', 'Throughput_MB_s', 'Energy_uJ', 'Power_W', 'StackUsage_B', 'HeapUsage_B']
    
    # base_df is a filtered version of dataFrame that only includes rows where the 'Map' column is 'AES-GCM standard'. 
    # It is indexed by the 'Fase' column and only includes the specified metrics.
    base_df = dataFrame[dataFrame['Map'] == 'AES-GCM standard'].set_index('Fase')[metrics]

    # For each metric in the metrics list, calculate the overhead percentage compared to the base values from base_df.
    for met in metrics[0:-1]:  # Exclude the last metric (HeapUsage_B) from the loop
        base_val = dataFrame['Fase'].map(base_df[met])
        column_name = f'Overhead_{met}_%'

        # Calculate the overhead percentage for the current metric and store it in a new column in dataFrame.
        # The formula used is: ((current value - base value) / base value) * 100
        dataFrame[column_name] = ((dataFrame[met] - base_val) / base_val) * 100

    # After calculating the overhead percentages for all specified metrics, round the values in dataFrame to two decimal places.
    cols_to_round = [col for col in dataFrame.columns if col != 'Bit_Entropy']
    dataFrame[cols_to_round] = dataFrame[cols_to_round].round(2)

    # Finally, write the updated DataFrame back to the 'results.csv' file, overwriting it with the new data that includes the overhead calculations.
    dataFrame.to_csv('results.csv', index=False)

if __name__ == "__main__":
    calc_overhead()