import networkx as nx
import matplotlib.pyplot as plt

def getFunctionMemoryUsage(line):
    parts = line.split('\t')
    funPath = parts[0].split(':')

    return funPath[-1], parts[1]

def getEdge(line):
    clean = line.replace('{', '').replace('}', '').replace('"', '')
    parts = clean.split(' ')

    n2Parts = parts[5].split(':')

    if len(n2Parts) == 2:
        return parts[3], n2Parts[1]
    else:
        return parts[3], n2Parts[0]

if __name__ == "__main__":
    ciPath = "run_info/aes.ci"
    suPath = "run_info/aes.su"

    G = nx.DiGraph()
    G.add_node("__stack_chk_fail", peso = 0)

    with open(suPath, 'r') as su:
        for line in su:
            fun, mem = getFunctionMemoryUsage(line)
            G.add_node(fun, peso = mem)

    with open(ciPath, 'r') as ci:
        for line in ci:
            if line[0:4] == "edge":
                n1, n2 = getEdge(line)
                G.add_edge(n1, n2)

    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='lightblue', font_weight='bold', node_size=2500)
    plt.draw