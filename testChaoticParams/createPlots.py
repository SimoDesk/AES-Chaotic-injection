import argparse
import re
from pathlib import Path
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent

# Define the metrics and their ideal values
METRICS = {
    "hamming": ("Average Hamming Distance", 64.0),
    "differing_bits": ("Average of Differing Bits (%)", 50.0),
}

# Define the paths to the CSV files containing the test results
TEST_FILES = {
    "Avalanche effect": SCRIPT_DIR / "avalancheEffect_results.csv",
    "Key sensitivity": SCRIPT_DIR / "keySensitivity_results.csv",
}

MAP_ORDER = (
    "logistic",
    "tent",
    "henon",
    "arnold",
    "sine",
    "chebyshev",
    "lorenz",
    "chen",
    "rossler",
)

# Define a function to load the CSV files into pandas DataFrames
def load_df(path, col_name):
    df = pd.read_csv(path, decimal=",")

    df["Mappa"] = df["Mappa"].astype(str).str.strip()

    # Convert the specified columns to numeric, replacing commas with dots for decimal representation
    for c in ["alfa", "beta", col_name]:
        df[c] = pd.to_numeric(df[c].astype(str).str.replace(",", "."))

    return df

def createPlots():
    # Parse command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--metric", choices=METRICS, default="hamming")
    parser.add_argument("--output-dir", type=Path, default=SCRIPT_DIR / "plots")
    args = parser.parse_args()

    # Create the output directory if it doesn't exist
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Load the CSV files and prepare the data for plotting
    col, ideal = METRICS[args.metric]
    dfs = {name: load_df(path, col) for name, path in TEST_FILES.items()}
    vmax = max(1.0, max((df[col] - ideal).abs().max() for df in dfs.values()))

    # Create plots for each unique map in the data
    available_maps = set(dfs["Avalanche effect"]["Mappa"])
    maps = [map_name for map_name in MAP_ORDER if map_name in available_maps]

    for m in maps:

        # Create a figure with two subplots for the two test types
        fig, axes = plt.subplots(1, 2, figsize=(15, 6), constrained_layout=True)

        # Loop through the test types and create heatmaps for each
        for ax, (test_name, df) in zip(axes, dfs.items()):
            grid = df[df["Mappa"] == m].pivot(index="alfa", columns="beta", values=col)
            vals, devs = grid.to_numpy(), np.abs(grid.to_numpy() - ideal)

            img = ax.imshow(devs, cmap="RdYlGn_r", vmin=0, vmax=vmax, aspect="auto")

            ax.set(title=test_name, xlabel="beta", ylabel="alfa")
            ax.set_xticks(range(len(grid.columns)), [f"{b:g}" for b in grid.columns])
            ax.set_yticks(range(len(grid.index)), [f"{a:g}" for a in grid.index])

            ax.tick_params(axis="x", rotation=45)

            ax.set_xticks(np.arange(-0.5, len(grid.columns), 1), minor=True)
            ax.set_yticks(np.arange(-0.5, len(grid.index), 1), minor=True)

            ax.grid(which="minor", color="white", linestyle="-", linewidth=1)

            ax.tick_params(which="minor", bottom=False, left=False)

            # Add text annotations to each cell in the heatmap
            for (i, j), val in np.ndenumerate(vals):
                dev = devs[i, j]
                ax.text(j, i, f"{val:.2f}\n({dev:.2f})", ha="center", va="center",
                        color="black" if dev < vmax * 0.55 else "white", fontsize=8)

            fig.colorbar(img, ax=ax, label=f"Absolute distance from {ideal:g}")

        # Set the title for the entire figure and save it to the output directory
        fig.suptitle(f"{m} - {col}\nTarget: {ideal:g} | Cell text: value (absolute distance from target)", fontsize=14)

        fig.savefig(args.output_dir / f"{m}_{args.metric}.png", dpi=160)
        
        plt.close(fig)

if __name__ == "__main__":
    createPlots()