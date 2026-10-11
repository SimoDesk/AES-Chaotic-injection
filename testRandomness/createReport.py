import ast
import csv
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parent

INPUT_CSV = BASE_DIR / "nist_results.csv"
REPORT_DIR = BASE_DIR / "nist_report"
SUMMARY_CSV = REPORT_DIR / "summary_by_test.csv"
P_VALUES_CSV = REPORT_DIR / "p_values.csv"
SUCCESS_HEATMAP = REPORT_DIR / "success_rate_heatmap.png"
PVALUE_HISTOGRAM = REPORT_DIR / "p_value_distributions.png"
PVALUE_BOXPLOT = REPORT_DIR / "p_value_boxplot.png"
ALPHA = 0.01


# parse_result takes a serialized string representation of a Python object and returns the corresponding Python object.
def parse_result(string_in):
    # Normalize the input string by replacing NumPy data types with their corresponding Python types and removing any unnecessary characters.
    normalized = re.sub(
        r"np\.(?:float64|float32|int64|int32)\(", "(", string_in
    )

    # Replace NumPy boolean types with their corresponding Python boolean types.
    normalized = normalized.replace("np.True_", "True").replace("np.False_", "False")

    # Return the evaluated Python object using ast.literal_eval, which safely evaluates a string containing a Python literal or container display.
    return ast.literal_eval(normalized)


# extract_components takes a test name and a serialized result string, 
# and returns a list of tuples containing the component name, p-value, and pass/fail status for each component in the test result
# Return (component name, p-value, status) for one NIST result.
def extract_components(test_name, string_in):
    # result is a tuple of tuples, where each inner tuple contains the component name, p-value, and pass/fail status
    result = parse_result(string_in)

    # Determine the index of the p-value in the result tuple based on the test name
    # For "Serial test", the p-value is at index 0; for "Random Excursions", it's at index 3; for other tests, it's at index 0
    if "Serial test" in test_name:
        components, p_index = result, 0
    elif "Random Excursions" in test_name:
        components, p_index = result, 3
    else:
        components, p_index = (result,), 0

    # extracted is a list of tuples containing the component name, p-value, and pass/fail status for each component in the test result
    extracted = []
    for component in components:
        # for each component, check if it's a tuple or list and if the last element is a boolean (pass/fail status)
        # If not, raise a ValueError with the test name and the component
        if not isinstance(component, (tuple, list)) or not isinstance(component[-1], bool):
            raise ValueError(f"Formato inatteso per {test_name}: {component!r}")

        # Append a tuple containing the component name (as a string), the p-value (as a float), and the pass/fail status (as a boolean) to the extracted list
        extracted.append((str(component[0]), float(component[p_index]), component[-1]))

    return extracted


# load_results reads the input CSV and returns a list of dictionaries with the following keys:
# - "Mappa": the map name
# - "Seed": the seed value (if present)
# - "Test": the test name
# - "Componente": the component name
# - "P-Value": the p-value
# - "Passato": whether the test passed (True/False)
def load_results():
    # details is a list of dictionaries, each representing a single test result
    details = []
    with INPUT_CSV.open(newline="", encoding="utf-8") as input_file:
        for row_number, row in enumerate(csv.DictReader(input_file), start=2):
            # Extract components from the "Test" and "Risultato (P-Value, Status)" columns
            # If the row is malformed, raise a ValueError with the row number
            try:
                components = extract_components(row["Test"], row["Risultato (P-Value, Status)"])
            except (KeyError, ValueError, SyntaxError) as error:
                raise ValueError(f"Impossibile interpretare la riga {row_number}") from error

            # For each component, create a dictionary with the relevant information and append it to the details list
            for component, p_value, passed in components:
                details.append(
                    {
                        "Mappa": row["Mappa"],
                        "Seed": row.get("Seed", ""),
                        "Test": row["Test"],
                        "Componente": component,
                        "P-Value": p_value,
                        "Passato": passed,
                    }
                )
    return details


# build_summary takes a list of test result details which are dictionaries containing information about each test execution, 
# and returns a summary of the results grouped by map and test name.
def build_summary(details):
    # executions is a defaultdict that groups test results by (map name, seed, test name) and stores a list of corresponding details for each group.
    executions = defaultdict(list)
    for detail in details:
        executions[(detail["Mappa"], detail["Seed"], detail["Test"])].append(detail)

    # grouped is a defaultdict that groups the executions by (map name, test name) and stores a list of dictionaries containing the pass/fail status and p-values for each execution.
    grouped = defaultdict(list)
    for (map_name, _seed, test_name), values in executions.items():
        grouped[(map_name, test_name)].append(
            {
                "passed": all(value["Passato"] for value in values),
                "p_values": [value["P-Value"] for value in values],
            }
        )

    # summary is a list of dictionaries containing the summary statistics for each (map name, test name) group, including the number of executions, 
    # successes, failures, success percentage, minimum p-value, median p-value, mean p-value, and the count of p-values below the significance level (ALPHA).
    summary = []
    for (map_name, test_name), values in sorted(grouped.items()):
        p_values = [p for value in values for p in value["p_values"]]
        successes = sum(value["passed"] for value in values)
        sorted_p_values = sorted(p_values)

        summary.append(
            {
                "Mappa": map_name,
                "Test": test_name,
                "Esecuzioni": len(values),
                "Successi": successes,
                "Fallimenti": len(values) - successes,
                "Percentuale successo": round(100 * successes / len(values), 2),
                "P-value minimo": min(p_values),
                "P-value mediano": sorted_p_values[len(sorted_p_values) // 2],
                "P-value medio": sum(p_values) / len(p_values),
                "P-value < 0.01": sum(p < ALPHA for p in p_values),
            }
        )

    return summary


# write_csv takes a file path and a list of dictionaries (rows) and writes the data to a CSV file at the specified path.
def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# create_plots generates visualizations based on the test result details and summary statistics.
# The three plots generated are:
# 1. A heatmap showing the success percentage for each map and test combination.
# 2. A histogram showing the distribution of p-values for each map.
# 3. A boxplot showing the distribution of p-values for each map.
def create_plots(details, summary):
    # Heatmap of success percentages by map and test --------------------------------
    maps = sorted({row["Mappa"] for row in summary})
    tests = sorted({row["Test"] for row in summary})
    rates = {
        (row["Mappa"], row["Test"]): row["Percentuale successo"]
        for row in summary
    }

    fig, ax = plt.subplots(figsize=(16, 8))
    matrix = [[rates[(map_name, test)] for map_name in maps] for test in tests]
    image = ax.imshow(matrix, vmin=0, vmax=100, aspect="auto", cmap="RdYlGn")
    ax.set_xticks(range(len(maps)), maps, rotation=45, ha="right")
    ax.set_yticks(range(len(tests)), [test[:35] for test in tests])
    ax.set_xlabel("Map")
    ax.set_ylabel("NIST test")
    ax.set_title("Percentage of successful executions by map and test")
    fig.colorbar(image, ax=ax, label="successes (%)")
    fig.tight_layout()
    fig.savefig(SUCCESS_HEATMAP, dpi=180)
    plt.close(fig)
    # ------------------------------------------------------------------------------


    # Histogram and boxplot of p-values by map --------------------------------------
    values_by_map = {
        map_name: [row["P-Value"] for row in details if row["Mappa"] == map_name]
        for map_name in maps
    }
    fig, axes = plt.subplots(2, 5, figsize=(18, 7), sharex=True, sharey=True)
    for axis, map_name in zip(axes.flat, maps):
        axis.hist(values_by_map[map_name], bins=10, range=(0, 1), edgecolor="black")
        axis.axvline(ALPHA, color="red", linestyle="--", linewidth=1)
        axis.set_title(map_name)
        axis.set_xlabel("p-value")
        axis.set_ylabel("Frequency")
    fig.suptitle("P-values distribution ​​per map")
    fig.tight_layout()
    fig.savefig(PVALUE_HISTOGRAM, dpi=180)
    plt.close(fig)
    # -----------------------------------------------------------------------------


    # Boxplot of p-values by map ---------------------------------------------------
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.boxplot([values_by_map[map_name] for map_name in maps], tick_labels=maps)
    ax.axhline(ALPHA, color="red", linestyle="--", label="α = 0,01")
    ax.legend(bbox_to_anchor=(1.01, 1), loc="lower center")
    ax.set_ylabel("p-value")
    ax.set_title("P-values distribution per map")   
    fig.autofmt_xdate(rotation=45)
    fig.tight_layout()
    fig.savefig(PVALUE_BOXPLOT, dpi=180)
    plt.close(fig)
    # -----------------------------------------------------------------------------


# create_report is the main function that leads the process of generating the report. 
def create_report():
    # Check if the input CSV file exists
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"File di input non trovato: {INPUT_CSV}")

    # Create the report directory if it doesn't exist
    REPORT_DIR.mkdir(exist_ok=True)

    # Load results and build summary
    details = load_results()
    summary = build_summary(details)

    # Write the summary and p-values to CSV files
    write_csv(SUMMARY_CSV, summary)
    write_csv(P_VALUES_CSV, [{**detail, "Passato": str(detail["Passato"])} for detail in details],)

    # Generate plots
    create_plots(details, summary)


if __name__ == "__main__":
    create_report()