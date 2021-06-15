#!/usr/bin/env python

import argparse
import networkx as nx

def node_name (name):
  if is_cg:
    return "\"{%s}\"" % name
  else:
    return "\"{%s:" % name

def parse_edges (line):
   edges = line.split ( )
   n1_name = node_name (edges[0])
   n1_list = filter (lambda (_, d): 'label' in d and n1_name in d['label'], G.nodes (data=True))
   if len (n1_list) > 0:
      (n1, _) = n1_list[0]
      for i in range (2, len(edges)):
        n2_name = node_name (edges[i])
        n2_list = filter (lambda (_, d): 'label' in d and n2_name in d['label'], G.nodes (data=True))
        if len (n2_list) > 0:
          (n2, _) = n2_list[0]
          if G.has_edge (n1, n2):
            print "[x] %s -> %s" % (n1_name, n2_name)
          else:
            print "[v] %s -> %s" % (n1_name, n2_name)
            G.add_edge(n1,n2)
            was_added = 1
#   else :
#     print "Could not find %s" % n1_name       

# Main function
if __name__ == '__main__':
  is_cg = 1
  was_added = 0
  parser = argparse.ArgumentParser ()    
  parser.add_argument ('-d', '--dot', type=str, required=True, help="Path to dot-file representing the graph")
  parser.add_argument ('-e', '--extra_edges', type=str, required=True, help="Extra edges to add to graph")
  args = parser.parse_args ()

  print "\nParsing %s .." % args.dot 
  G = nx.Graph(nx.drawing.nx_pydot.read_dot (args.dot))
  print nx.info (G)

  before = nx.number_connected_components (G)

  is_cg = 1 if "Name: Call graph" in nx.info (G) else 0
  print "\nWorking in %s mode.." % ("CG" if is_cg else "CFG")

  print "Adding edges.."
  with open(args.extra_edges, "r") as f:
    edges = map(parse_edges, f.readlines ())

  print "\n############################################"
  print "#Connected components reduced from %d to %d." % (before, nx.number_connected_components (G))
  print "############################################"


#  print "\nWriting %s .." % args.dot
  if was_added:
    nx.drawing.nx_pydot.write_dot(G, args.dot)
