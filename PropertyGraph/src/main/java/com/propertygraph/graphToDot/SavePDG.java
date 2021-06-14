package com.propertygraph.graphToDot;

import com.platform.demo.MainTest;
import com.platform.demo.service.Common;
import com.propertygraph.ast.ASTVisitor;
import com.propertygraph.cfg.node.CFGNodeFactory;
import com.propertygraph.pdg.PDG;
import com.propertygraph.pdg.edge.PDGControlDependenceEdge;
import com.propertygraph.pdg.edge.PDGDataDependenceEdge;
import com.propertygraph.pdg.edge.PDGEdge;
import com.propertygraph.pdg.edge.PDGExecutionDependenceEdge;
import com.propertygraph.pdg.node.*;
import com.propertygraph.pe.MethodInfo;
import org.eclipse.jdt.core.dom.CompilationUnit;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SavePDG {
    public static void save(File f){
        String outPaths = f.getParent() + File.separator + "PDG";
        File out = new File(outPaths);

        if (out.exists()){
            MainTest.deleteFile(out.listFiles());
        }

        if (!out.exists()){
            out.mkdirs();
        }

        List<File> files = MainTest.getFiles(f);
        for (File file : files) {

            final List<MethodInfo> methods = new ArrayList<MethodInfo>();
            final CompilationUnit unit = ASTVisitor.createAST(file);
            final List<MethodInfo> m = new ArrayList<MethodInfo>();
            final ASTVisitor visitor = new ASTVisitor(
                    file.getAbsolutePath(), unit, methods);
            unit.accept(visitor);
            methods.addAll(m);
            int createdGraphNumber = 0;

            //TODO 下载文件位置需要改
            String outPath = outPaths + File.separator + file.getName().replace(".java", "_pdg.dot");
            final BufferedWriter writer;
            try {
                writer = new BufferedWriter(new FileWriter(outPath));
                writer.write("digraph PDG {");
                writer.newLine();

                for (final MethodInfo method : methods) {

                    final PDG pdg = new PDG(method, new PDGNodeFactory(),
                            new CFGNodeFactory(), true, true, true);
                    pdg.build();
                    writePDG(pdg, createdGraphNumber++, writer);
                }

                writer.write("}");
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void writePDG(final PDG pdg,
                          final int createdGraphNumber,
                          final BufferedWriter writer) throws IOException {
        final MethodInfo method = pdg.unit;

        writer.write("subgraph cluster");
        writer.write(Integer.toString(createdGraphNumber));
        writer.write(" {");
        writer.newLine();

        writer.write("label = \"");
        writer.write(Common.getMethodSignature(method));
        writer.write("\";");
        writer.newLine();

        final Map<PDGNode<?>, Integer> nodeLabels = new HashMap<PDGNode<?>, Integer>();
        //final SortedSet<PDGNode<?>> nodes = pdg.getAllNodes();
        for (final PDGNode<?> node : pdg.getAllNodes()) {
            nodeLabels.put(node, nodeLabels.size());
        }

        for (final Map.Entry<PDGNode<?>, Integer> entry : nodeLabels.entrySet()) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(entry.getValue()));
            writer.write(" [style = filled, label = \"");
            writer.write(entry.getKey().getText().replace("\"", "\\\"")
                    .replace("\\\\\"", "\\\\\\\""));
            writer.write("\"");

            final PDGNode<?> node = entry.getKey();
            if (node instanceof PDGMethodEnterNode) {
                writer.write(", fillcolor = aquamarine");
            } else if (pdg.getExitNodes().contains(node)) {
                writer.write(", fillcolor = deeppink");
            } else if (node instanceof PDGParameterNode) {
                writer.write(", fillcolor = tomato");
            } else {
                writer.write(", fillcolor = white");
            }

            if (node instanceof PDGControlNode) {
                writer.write(", shape = diamond");
            } else if (node instanceof PDGParameterNode) {
                writer.write(", shape = box");
            } else {
                writer.write(", shape = ellipse");
            }

            writer.write("];");
            writer.newLine();
        }

        for (final PDGEdge edge : pdg.getAllEdges()) {
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.fromNode)));
            writer.write(" -> ");
            writer.write(Integer.toString(createdGraphNumber));
            writer.write(".");
            writer.write(Integer.toString(nodeLabels.get(edge.toNode)));
            if (edge instanceof PDGDataDependenceEdge) {
                writer.write(" [style = solid, label=\""
                        + edge.getDependenceString() + "\"]");
            } else if (edge instanceof PDGControlDependenceEdge) {
                writer.write(" [style = dotted, label=\""
                        + edge.getDependenceString() + "\"]");
            } else if (edge instanceof PDGExecutionDependenceEdge) {
                writer.write(" [style = bold, label=\""
                        + edge.getDependenceString() + "\"]");
            }
            writer.write(";");
            writer.newLine();
        }

        writer.write("}");
        writer.newLine();
    }

}
