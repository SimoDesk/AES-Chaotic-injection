from pathlib import Path
import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent

AV_FILE = SCRIPT_DIR / "avalancheEffect_results.csv"
KS_FILE = SCRIPT_DIR / "keySensitivity_results.csv"

# Define a function to load and clean the CSV files
def load_clean(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in ["Average Hamming Distance", "Distance from perfection", "Average of Differing Bits (%)"]:
        df[col] = df[col].astype(str).str.replace(",", ".").astype(float)
    return df


def createLeaderBoard():
    av = load_clean(AV_FILE)
    ks = load_clean(KS_FILE)

    # Merge the two DataFrames on Mappa, alfa, and beta
    df = pd.merge(av, ks, on=["Mappa", "alfa", "beta"], suffixes=("_av", "_ks"))

    # Calculate a score for each row.
    # The score depends on three metrics: sum of deviations (L1), Euclidean distance (L2), and maximum deviation (L_inf).
    df["dev_av"] = df["Distance from perfection_av"]
    df["dev_ks"] = df["Distance from perfection_ks"]

    # The first metric is the sum of deviations (L1 norm), which gives an overall measure of how far the results are from the ideal values.
    # S1 = |dev_av| + |dev_ks|
    df["sum_dev"] = (df["dev_av"] + df["dev_ks"]).round(4)

    # The second metric is the Euclidean distance (L2 norm), which penalizes larger deviations more heavily than smaller ones.
    # S2 = sqrt(dev_av^2 + dev_ks^2)
    df["euclid_dev"] = np.sqrt(df["dev_av"] ** 2 + df["dev_ks"] ** 2).round(4)

    # The third metric is the maximum deviation (L_inf norm), which tries to minimize the worst-case scenario across both tests.
    # S3 = max(|dev_av|, |dev_ks|)
    df["max_dev"] = np.maximum(df["dev_av"], df["dev_ks"]).round(4)


    # Sort the DataFrame based on the three metrics to create a ranking of (alfa, beta) pairs for each map.
    df = df.sort_values(["Mappa", "sum_dev", "max_dev", "euclid_dev"])
    df["Rank"] = df.groupby("Mappa").cumcount() + 1

    # Save the complete ranking to a CSV file
    cols = [
        "Mappa", "Rank", "alfa", "beta",
        "Average Hamming Distance_av", "dev_av",
        "Average Hamming Distance_ks", "dev_ks",
        "sum_dev", "max_dev", "euclid_dev",
    ]
    ranking = df[cols]

    # Save the ranking to a CSV file with semicolon as separator and comma as decimal point
    out_path = SCRIPT_DIR / "ranking_alfa_beta.csv"
    ranking.to_csv(out_path, index=False, sep=";", decimal=",")


if __name__ == "__main__":
    createLeaderBoard()