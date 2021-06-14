package com.platform.astdemo.generator;

import org.eclipse.jdt.core.dom.ASTNode;

import com.platform.astdemo.structure.MyASTNode;
import com.platform.astdemo.structure.MyMethodNode;

public class ASTtoDOT {

	/**
	 * Convert a method node to .dot string
	 * @param m
	 * @return
	 */
	public static String ASTtoDotParser(MyMethodNode m, int num) {
		//String str = "digraph \"DirectedGraph\" {\n";
		String str = "subgraph cluster " + String.valueOf(num) + " {\n";
		// name
		str += ("graph [label = \"" + m.methodNode.getName() + "\", labelloc=t, concentrate = true];\n");
		for (MyASTNode mn : m.nodeList) {
			ASTNode astNode = mn.astNode;
			int hashcode = astNode.hashCode();
			int nodeType = astNode.getNodeType();
			str += ("\"" + String.valueOf(hashcode) + "\" [ label=\""+buildLabel(mn)+"\" type=" + String.valueOf(nodeType) + " startLineNumber="
					+ String.valueOf(mn.startLineNum)+" endLineNumber="
							+ String.valueOf(mn.endLineNum) + " ]\n");
		}
		for (int[] k : m.mapping) {
			int pHashcode = k[0];
			int hashcode = k[1];
			str += ("\"" + String.valueOf(pHashcode) + "\" -> \"" + String.valueOf(hashcode) + "\"\n");
		}
		str += "}\n";
		return str;
	}
	
	/**
	 * Configure the label, i.e., what you want to display in the visulization
	 * @param node
	 * @return
	 */
	public static String buildLabel(MyASTNode node) {
		String contentString=node.astNode.toString().replace("\n", " ").replace("\"", "\\\"").replace("  ", " ");
		String nodeType=ASTNode.nodeClassForType(node.astNode.getNodeType()).getName().replace("org.eclipse.jdt.core.dom.", "");
		return "("+contentString+","+nodeType+","+node.startLineNum+","+node.endLineNum+")";
	}
}
