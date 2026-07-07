import os
import webbrowser
from pyvis.network import Network
import networkx as nx

if __name__ == "__main__":
    import sys

    in_file = sys.argv[1]
    out = sys.argv[2]
    # 1. Initialize a Pyvis network (notebook=False ensures it opens in a standard browser)
    # Add cdn_resources="remote" to force internet-based script loading
    net = Network(
        notebook=False,
        cdn_resources="remote",
        height="750px",
        width="100%",
        bgcolor="#222222",
        font_color="white",
    )

    G = nx.read_graphml(in_file)
    print(G.number_of_nodes())

    # clean_G = nx.Graph()

    # # Copy just the node IDs and edge connections
    # clean_G.add_nodes_from(G.nodes())
    # clean_G.add_edges_from(G.edges())

    # # (Optional) Give them basic string labels so they aren't blank
    # for node in clean_G.nodes():
    #     clean_G.nodes[node]["label"] = str(node)
    # # --------------------------

    # # Consume the CLEANED graph instead of the raw one
    # net.from_nx(clean_G)

    # 2. Consume your existing NetworkX graph 'G'
    net.from_nx(G)

    # 3. Generate and open the interactive HTML file
    net.write_html(out, open_browser=False)

    # 1. Get the absolute path of your local HTML file
    file_path = os.path.abspath(out)

    # 2. Convert the path into a file:// URL and open it
    webbrowser.open(f"file://{file_path}")
