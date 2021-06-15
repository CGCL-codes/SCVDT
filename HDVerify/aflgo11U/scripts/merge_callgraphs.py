#!/usr/bin/env python3

import argparse
import networkx as nx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--out', type=str, required=True, help="Path to output dot file.")
    parser.add_argument('dot', nargs='+', help="Path to input dot files.")

    args = parser.parse_args()

    G = nx.DiGraph()
    for dot in args.dot:
        G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot(dot)))

    with open(args.out, 'w') as f:
        nx.drawing.nx_pydot.write_dot(G, f)


# Main function
if __name__ == '__main__':
    main()
