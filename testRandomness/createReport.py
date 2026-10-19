import ast
import csv
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from scipy.special import gammaincc


BASE_DIR = Path(__file__).resolve().parent

INPUT_CSV = BASE_DIR / "nist_results.csv"
REPORT_DIR = BASE_DIR / "nist_report"
SUMMARY_CSV = REPORT_DIR / "summary_by_test.csv"
EXECUTION_SUMMARY_CSV = REPORT_DIR / "summary_by_execution.csv"
UNIFORMITY_CSV = REPORT_DIR / "uniformity_by_test.csv"
P_VALUES_CSV = REPORT_DIR / "p_values.csv"
SUCCESS_HEATMAP = REPORT_DIR / "success_rate_heatmap.png"
PVALUE_HISTOGRAM = REPORT_DIR / "p_value_distributions.png"
PVALUE_BOXPLOT = REPORT_DIR / "p_value_boxplot.png"
PROPORTION_VERDICTS = REPORT_DIR / "nist_proportion_verdicts.png"
AVERAGE_SUCCESS_RATE = REPORT_DIR / "average_success_rate.png"
UNIFORMITY_VERDICTS = REPORT_DIR / "nist_uniformity_verdicts.png"

ALPHA = 0.01
TARGET_PROPORTION = 1 - ALPHA
UNIFORMITY_ALPHA = 0.0001
MINIMUM_SEQUENCES = 55

MAP_ORDER = (
    "standard",
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

    # for each component in the test result, extract the component name, p-value, and pass/fail status and append it to the extracted list
    for index, component in enumerate(components, start=1):

        # if the component is not a tuple or list, or if the last element of the component is not a boolean, raise a ValueError
        if not isinstance(component, (tuple, list)) or not isinstance(component[-1], bool):
            raise ValueError(f"Formato inatteso per {test_name}: {component!r}")

        # Determine the component name based on the test name and the length of the component tuple/list
        # if the test is "Serial test", the component name is "Serial component {index}"
        # if the component has more than 2 elements, the component name is the first element
        # otherwise, the component name is the test name
        if "Serial test" in test_name:
            component_name = f"Serial component {index}"
        elif len(component) > 2:
            component_name = str(component[0])
        else:
            component_name = test_name
        extracted.append((component_name, float(component[p_index]), component[-1]))

    return extracted


# load_results reads the input CSV and returns a list of dictionaries with the following keys:
# - "Map": the map name
# - "Seed": the seed value (if present)
# - "Test": the test name
# - "Component": the component name
# - "P-Value": the p-value
# - "Passed": whether the test passed (True/False)
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
                        "Map": row["Mappa"],
                        "Seed": row.get("Seed", ""),
                        "Test": row["Test"],
                        "Component": component,
                        "P-Value": p_value,
                        "Passed": passed,
                    }
                )
    return details


# nist_proportion_bounds calculates the lower and upper bounds for the proportion of successful tests based on the NIST guidelines.
# The bounds are calculated using the formula:
# margin = 3 * sqrt(TARGET_PROPORTION * (1 - TARGET_PROPORTION) / sequence_count)
# lower_bound = TARGET_PROPORTION - margin
# upper_bound = TARGET_PROPORTION + margin
def nist_proportion_bounds(sequence_count):
    margin = 3 * (
        TARGET_PROPORTION * (1 - TARGET_PROPORTION) / sequence_count
    ) ** 0.5
    return TARGET_PROPORTION - margin, TARGET_PROPORTION + margin


# build_summary takes a list of test result details and returns a summary of the results, such as
# the number of sequences, successes, failures, success rate, NIST bounds, minimum p-value, median p-value, average p-value, and the count of p-values below the significance level (ALPHA).
def build_component_summary(details):
    # grouped is a defaultdict that groups the executions by (map name, test name) and stores a list of dictionaries containing the pass/fail status and p-values for each execution.
    grouped = defaultdict(list)
    for detail in details:
        grouped[(detail["Map"], detail["Test"], detail["Component"])].append(detail)

    # summary is a list of dictionaries containing the summary statistics for each (map name, test name) group, including the number of executions, 
    # successes, failures, success percentage, minimum p-value, median p-value, mean p-value, and the count of p-values below the significance level (ALPHA).
    summary = []
    for (map_name, test_name, component), values in sorted(grouped.items()):
        p_values = [value["P-Value"] for value in values]
        successes = sum(value["Passed"] for value in values)
        proportion = successes / len(values)
        lower, upper = nist_proportion_bounds(len(values))
        ordered = sorted(p_values)

        summary.append(
            {
                "Map": map_name,
                "Test": test_name,
                "Component": component,
                "Sequence": len(values),
                "Succeses": successes,
                "Failures": len(values) - successes,
                "Success rate": round(100 * proportion, 2),
                "Lower NIST bound": round(100 * lower, 2),
                "Upper NIST bound": round(100 * upper, 2),
                "NIST proportion assessment": (
                    "PASS" if lower <= proportion <= upper else "FAIL"
                ),
                "Minimum P-value": min(p_values),
                "Median P-value": ordered[len(ordered) // 2],
                "Average P-value": sum(p_values) / len(p_values),
                "P-value < 0.01": sum(p < ALPHA for p in p_values),
            }
        )

    return summary


# build_execution_summary takes a list of test result details and returns a summary of the results grouped by (map name, seed, test name), such as
# the number of passed subtests, total subtests, and whether the execution was completely successful.
def build_execution_summary(details):
    # grouped is a defaultdict that groups the executions by (map name, seed, test name) and stores a list of dictionaries containing the pass/fail status for each execution.
    grouped = defaultdict(list)
    for detail in details:
        grouped[(detail["Map"], detail["Seed"], detail["Test"])].append(detail)

    # summary is a list of dictionaries containing the summary statistics for each (map name, seed, test name) group, 
    # such as the number of passed subtests, total subtests, and whether the execution was completely successful.
    summary = []
    for (map_name, seed, test_name), values in sorted(grouped.items()):
        summary.append(
            {
                "Map": map_name,
                "Seed": seed,
                "Test": test_name,
                "Sub-tests passed": sum(value["Passed"] for value in values),
                "Total sub-tests": len(values),
                "Execution completely surpassed": all( value["Passed"] for value in values),
            }
        )

    return summary


# build_uniformity_summary takes a list of test result details and returns a summary of the uniformity of the p-values for each (map name, test name, component) group,
# including the number of sequences, counts of p-values in each interval, chi-square statistic,
# uniformity p-value, whether the sample size is sufficient, and the overall NIST assessment
def build_uniformity_summary(details):
    # grouped is a defaultdict that groups the executions by (map name, test name, component) and stores a list of p-values for each execution.
    grouped = defaultdict(list)
    for detail in details:
        grouped[(detail["Map"], detail["Test"], detail["Component"])].append(detail["P-Value"])

    # summary is a list of dictionaries containing the summary statistics for each (map name, test name, component) group,
    # including the number of sequences, counts of p-values in each interval, chi-square statistic, uniformity p-value, whether the sample size is sufficient, and the overall NIST assessment.
    summary = []
    for (map_name, test_name, component), p_values in sorted(grouped.items()):
        # Calculate the number of sequences, counts of p-values in each interval, expected counts, chi-square statistic, and uniformity p-value

        # Every formula is taken from the NIST SP 800-22 Rev. 1a, Section 3.2.2, "Uniformity of P-values", and the chi-square test is used to assess the uniformity of the p-values.
        sample_size = len(p_values)
        counts = [sum(index / 10 <= p_value < (index + 1) / 10 for p_value in p_values) for index in range(10)]
        expected = sample_size / 10
        chi_square = sum((count - expected) ** 2 / expected for count in counts)
        uniformity_p_value = float(gammaincc(9 / 2, chi_square / 2))
        sample_sufficient = sample_size >= MINIMUM_SEQUENCES

        summary.append(
            {
                "Map": map_name,
                "Test": test_name,
                "Component": component,
                "Sequence": sample_size,
                "Interval counts": ";".join(map(str, counts)),
                "Chi-squared": chi_square,
                "P-value uniformity": uniformity_p_value,
                "NIST theshold": UNIFORMITY_ALPHA,
                "NIST uniformity (p-value)": ("PASS" if uniformity_p_value >= UNIFORMITY_ALPHA else "FAIL"),
                "Minimum number of sequences": MINIMUM_SEQUENCES,
                "Sufficient sample": ("YES" if sample_sufficient else "NO"),
                "NIST Overall Assessment": (
                    "PASS"
                    if sample_sufficient and uniformity_p_value >= UNIFORMITY_ALPHA
                    else "FAIL"
                    if sample_sufficient
                    else "INSUFFICIENT"
                ),
            }
        )

    return summary


# write_csv takes a file path and a list of dictionaries (rows) and writes the data to a CSV file at the specified path.
def write_csv(path, rows):
    if not rows:
        return
    
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# create_plots generates visualizations based on the test result details and summary statistics.
# The three plots generated are:
# 1. A heatmap showing the success percentage for each map and test combination.
# 2. A histogram showing the distribution of p-values for each map.
# 3. A boxplot showing the distribution of p-values for each map.
# 4. A bar chart showing the proportion of PASS and FAIL verdicts for each map based on the NIST proportion assessment.
# 5. A bar chart showing the average success rate for each map, with a baseline for the AES standard.
# 6. A bar chart showing the proportion of PASS, FAIL, and INSUFFICIENT verdicts for each map based on the NIST overall assessment.
def create_plots(details, component_summary, uniformity_summary):
    # Heatmap of success percentages by map and test --------------------------------
    available_maps = {row["Map"] for row in component_summary}
    maps = [map_name for map_name in MAP_ORDER if map_name in available_maps]
    tests = sorted({row["Test"] for row in component_summary})
    
    grouped_rates = defaultdict(list)
    for row in component_summary:
        grouped_rates[(row["Map"], row["Test"])].append(row["Success rate"])

    matrix = [[sum(grouped_rates[(map_name, test)]) / len(grouped_rates[(map_name, test)]) for map_name in maps] for test in tests]
    fig, ax = plt.subplots(figsize=(16, 8))
    image = ax.imshow(matrix, vmin=0, vmax=100, aspect="auto", cmap="RdYlGn")

    ax.set_xticks(range(len(maps)), maps, rotation=45, ha="right")
    ax.set_yticks(range(len(tests)), [test[:35] for test in tests])
    ax.set_xlabel("Map")
    ax.set_ylabel("NIST test")
    ax.set_title("Percentage of successful executions by map and test")

    fig.colorbar(image, ax=ax, label="Successes (%)")
    fig.tight_layout()

    fig.savefig(SUCCESS_HEATMAP, dpi=180)

    plt.close(fig)
    # ------------------------------------------------------------------------------


    # Histogram and boxplot of p-values by map --------------------------------------
    values_by_map = {
        map_name: [row["P-Value"] for row in details if row["Map"] == map_name]
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
    # ------------------------------------------------------------------------------


    # Boxplot of p-values by map ---------------------------------------------------
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.boxplot([values_by_map[map_name] for map_name in maps], tick_labels=maps)
    ax.axhline(ALPHA, color="red", linestyle="--", label="alpha = 0.01")
    
    ax.set_ylabel("p-value")
    ax.set_title("P-values distribution per map")
    
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.15))
    
    fig.autofmt_xdate(rotation=45)
    fig.tight_layout()

    fig.savefig(PVALUE_BOXPLOT, dpi=180)

    plt.close(fig)
    # -----------------------------------------------------------------------------

    # Proportion verdicts and average success rates --------------------------------
    proportion_counts = {
        map_name: {verdict: sum(row["Map"] == map_name and row["NIST proportion assessment"] == verdict for row in component_summary)for verdict in ("PASS", "FAIL")}
        for map_name in maps
    }

    x_values = range(len(maps))
    passed = [proportion_counts[map_name]["PASS"] for map_name in maps]
    failed = [proportion_counts[map_name]["FAIL"] for map_name in maps]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x_values, passed, label="PASS", color="#2ca02c")
    ax.bar(x_values, failed, bottom=passed, label="FAIL", color="#d62728")

    ax.set_xticks(list(x_values), maps, rotation=45, ha="right")
    ax.set_ylabel("Number of components")
    ax.set_ylim(0, max(41, max(p + f for p, f in zip(passed, failed))) + 1)
    ax.set_title("NIST verdicts on sequence proportions")

    ax.legend()
    fig.tight_layout()

    fig.savefig(PROPORTION_VERDICTS, dpi=180)

    plt.close(fig)
    # -----------------------------------------------------------------------------

    # Average success rates --------------------------------------------------------
    average_rates = {
        map_name: sum(float(row["Success rate"]) for row in component_summary if row["Map"] == map_name) / sum(row["Map"] == map_name for row in component_summary)
        for map_name in maps
    }

    ordered_rates = [average_rates[map_name] for map_name in maps]
    baseline = average_rates["standard"]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(maps, ordered_rates, color="#4c78a8")
    ax.axhline(
        baseline,
        color="#d62728",
        linestyle="--",
        linewidth=1.5,
        label=f"AES standard ({baseline:.2f}%)",
    )

    ax.set_ylabel("Average success rate (%)")
    ax.set_ylim(min(ordered_rates) - 1, 100)
    ax.set_title("Average success rate per map")

    ax.tick_params(axis="x", rotation=45)
    ax.legend()

    for bar, rate in zip(bars, ordered_rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            rate + 0.1,
            f"{rate:.2f}%",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    fig.tight_layout()

    fig.savefig(AVERAGE_SUCCESS_RATE, dpi=180)

    plt.close(fig)
    # -----------------------------------------------------------------------------

    # Uniformity verdicts ----------------------------------------------------------
    uniformity_counts = {
        map_name: {verdict: sum(row["Map"] == map_name and row["NIST Overall Assessment"] == verdict for row in uniformity_summary) for verdict in ("PASS", "FAIL", "INSUFFICIENT")}
        for map_name in maps
    }

    uniformity_passed = [
        uniformity_counts[map_name]["PASS"] for map_name in maps
    ]
    uniformity_failed = [
        uniformity_counts[map_name]["FAIL"] for map_name in maps
    ]
    uniformity_insufficient = [
        uniformity_counts[map_name]["INSUFFICIENT"] for map_name in maps
    ]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x_values, uniformity_passed, label="PASS", color="#2ca02c")
    ax.bar(
        x_values,
        uniformity_failed,
        bottom=uniformity_passed,
        label="FAIL",
        color="#d62728",
    )
    ax.bar(
        x_values,
        uniformity_insufficient,
        bottom=[
            passed + failed
            for passed, failed in zip(uniformity_passed, uniformity_failed)
        ],
        label="INSUFFICIENT (<55 sequenze)",
        color="#f2cf5b",
    )

    ax.set_xticks(list(x_values), maps, rotation=45, ha="right")
    ax.set_ylabel("Number of components")
    ax.set_ylim(0, max(41, max(
        p + f + i
        for p, f, i in zip(
            uniformity_passed, uniformity_failed, uniformity_insufficient
        )
    )) + 1)
    ax.set_title("Uniformity of p-values ​​according to the NIST criterion")

    ax.legend()
    fig.tight_layout()

    fig.savefig(UNIFORMITY_VERDICTS, dpi=180)

    plt.close(fig)
    # -----------------------------------------------------------------------------
    


# create_report is the main function that leads the process of generating the report. 
def create_report():
    # Check if the input CSV file exists
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"File di input non trovato: {INPUT_CSV}")

    # Create the report directory if it doesn't exist
    REPORT_DIR.mkdir(exist_ok=True)

    # Load results and build summaries
    details = load_results()
    component_summary = build_component_summary(details)
    execution_summary = build_execution_summary(details)
    uniformity_summary = build_uniformity_summary(details)

    # Write the summaries to CSV files
    write_csv(SUMMARY_CSV, component_summary)
    write_csv(EXECUTION_SUMMARY_CSV, execution_summary)
    write_csv(UNIFORMITY_CSV, uniformity_summary)
    write_csv(P_VALUES_CSV, [{**detail, "Passed": str(detail["Passed"])} for detail in details],)

    # Generate plots for the report
    create_plots(details, component_summary, uniformity_summary)


if __name__ == "__main__":
    create_report()
