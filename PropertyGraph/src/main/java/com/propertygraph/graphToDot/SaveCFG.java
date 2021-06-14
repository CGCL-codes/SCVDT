package com.propertygraph.graphToDot;

import com.platform.demo.Config;
import com.platform.demo.MainTest;
import com.platform.demo.service.Common;
import com.propertygraph.ast.ASTVisitor;
import com.propertygraph.cfg.CFG;
import com.propertygraph.cfg.edge.CFGEdge;
import com.propertygraph.cfg.node.CFGControlNode;
import com.propertygraph.cfg.node.CFGNode;
import com.propertygraph.cfg.node.CFGNodeFactory;
import com.propertygraph.pe.MethodInfo;
import com.propertygraph.pe.ProgramElementInfo;
import org.eclipse.jdt.core.dom.CompilationUnit;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class SaveCFG {
    public static void save(File file){
        String outPaths = file.getParent() + File.separator + "CFG";
        File out = new File(outPaths);

        if (out.exists()){
            MainTest.deleteFile(out.listFiles());
        }

        if (!out.exists()){
            out.mkdirs();
        }

        List<File> files = MainTest.getFiles(file);
        try {
            for (File f : files) {
                final List<MethodInfo> methods = new ArrayList<MethodInfo>();
                final CompilationUnit unit = ASTVisitor.createAST(f);
                final List<MethodInfo> m = new ArrayList<MethodInfo>();
                final ASTVisitor visitor = new ASTVisitor(
                        f.getAbsolutePath(), unit, methods);
                unit.accept(visitor);
                methods.addAll(m);

                //String outPath = outDot.getAbsolutePath() + File.separator + file.getName().replaceAll("\\.java","_cfg.dot");
                String outPath = outPaths + File.separator + f.getName().replace(".java", "_cfg.dot");
                final BufferedWriter writer = new BufferedWriter(
                        new FileWriter(outPath));
                writer.write("digraph CFG {");
                writer.newLine();

                final CFGNodeFactory nodeFactory = new CFGNodeFactory();
                int createdGraphNumber = 0;
                for (final MethodInfo method : methods) {
                    final CFG cfg = new CFG(method, nodeFactory);
                    cfg.build();
                    cfg.removeSwitchCases();
                    cfg.removeJumpStatements();
                    writeMethodCFG(cfg, createdGraphNumber++, writer);
                }

                writer.write("}");
                writer.close();
            }
        }catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeMethodCFG(final CFG cfg,
                                final int createdGraphNumber,
                                final BufferedWriter writer) throws IOException {
        writer.write("subgraph cluster");
        writer.write(Integer.toString(createdGraphNumber));
        writer.write(" {");
        writer.newLine();

        writer.write("label = \"");
        writer.write(Common.getMethodSignature((MethodInfo) cfg.core));
        writer.write("\";");
        writer.newLine();

        final SortedSet<CFGEdge> edges = new TreeSet<CFGEdge>();
        for (final CFGNode<?> node : cfg.getAllNodes()) {
            edges.addAll(node.getBackwardEdges());
            edges.addAll(node.getForwardEdges());
        }

        final SortedSet<CFGNode<? extends ProgramElementInfo>> allNodes = new TreeSet<>();
        for (final CFGEdge edge : edges){
            allNodes.add(edge.fromNode);
            allNodes.add(edge.toNode);
        }

        final SortedMap<CFGNode<? extends ProgramElementInfo>, Integer> nodeLabels = new TreeMap<CFGNode<? extends ProgramElementInfo>, Integer>();
        for (final CFGNode<?> node : cfg.getAllNodes()) {
            nodeLabels.put(node, nodeLabels.size());
        }

        for (final Map.Entry<CFGNode<? extends ProgramElementInfo>, Integer> entry : nodeLabels
                .entrySet()) {

            final CFGNode<? extends ProgramElementInfo> node = entry.getKey();
            final Integer label = entry.getValue();

            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(label));
            writer.write(" [style = filled, label = \"");
            writer.write(node.getText().replace("\"", "\\\"")
                    .replace("\\\\\"", "\\\\\\\""));

            writer.write("\"");

            final CFGNode<? extends ProgramElementInfo> enterNode = cfg
                    .getEnterNode();
            final SortedSet<CFGNode<? extends ProgramElementInfo>> exitNodes = cfg
                    .getExitNodes();

            if (enterNode == node) {
                writer.write(", fillcolor = aquamarine");
            } else if (exitNodes.contains(node)) {
                writer.write(", fillcolor = deeppink");
            } else {
                writer.write(", fillcolor = white");
            }

            if (node instanceof CFGControlNode) {
                writer.write(", shape = diamond");
            } else {
                writer.write(", shape = ellipse");
            }

            writer.write("];");
            writer.newLine();
        }

        writeCFGEdges(cfg, nodeLabels, createdGraphNumber, writer);

        writer.write("}");
        writer.newLine();

    }

    private static void writeCFGEdges(
            final CFG cfg,
            final Map<CFGNode<? extends ProgramElementInfo>, Integer> nodeLabels,
            final int createdGraphNumber, final BufferedWriter writer)
            throws IOException {
        if (null == cfg) {
            return;
        }
        final SortedSet<CFGEdge> edges = new TreeSet<CFGEdge>();
        for (final CFGNode<?> node : cfg.getAllNodes()) {
            edges.addAll(node.getBackwardEdges());
            edges.addAll(node.getForwardEdges());
        }
        for (final CFGEdge edge : edges) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.fromNode)));
            writer.write(" -> ");
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.toNode)));
            writer.write(" [style = solid, label=\""
                    + edge.getDependenceString() + "\"];");
            writer.newLine();
        }
    }
}
