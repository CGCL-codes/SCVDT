package com.generatepdg.pdg.node;

import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.generatepdg.cfg.node.CFGControlNode;
import com.generatepdg.cfg.node.CFGNode;
import com.generatepdg.cfg.node.CFGNormalNode;
import com.generatepdg.pe.ExpressionInfo;
import com.generatepdg.pe.MethodInfo;
import com.generatepdg.pe.ProgramElementInfo;
import com.generatepdg.pe.StatementInfo;
import com.generatepdg.pe.VariableInfo;

public class PDGNodeFactory {

	private final ConcurrentMap<ProgramElementInfo, PDGNode<?>> elementToNodeMap;

	public PDGNodeFactory() {
		this.elementToNodeMap = new ConcurrentHashMap<ProgramElementInfo, PDGNode<?>>();
	}

	public PDGNode<?> makeNode(final CFGNode<?> node) {

		assert null != node : "\"node\" is null.";

		if (node instanceof CFGControlNode) {
			return this.makeControlNode(node.core);
		}

		else if (node instanceof CFGNormalNode) {
			return this.makeNormalNode(node.core);
		}

		else {
			assert false : "\"node\" is an invalid parameter.";
			return null;
		}
	}

	public synchronized PDGNode<?> makeControlNode(
			final ProgramElementInfo element) {

		assert null != element : "\"element\" is null.";

		PDGNode<?> node = this.elementToNodeMap.get(element);
		if (null != node) {
			return node;
		}

		if (element instanceof ExpressionInfo) {
			node = new PDGControlNode(element);
		}

		else if (element instanceof VariableInfo) {
			node = new PDGControlNode(element);
		}

		else if (element instanceof MethodInfo) {
			node = PDGMethodEnterNode.getInstance((MethodInfo) element);
		}

		else {
			assert false : "\"element\" is an invalid parameter.";
		}

		this.elementToNodeMap.put(element, node);

		return node;
	}

	public synchronized PDGNode<?> makeNormalNode(
			final ProgramElementInfo element) {

		assert null != element : "\"element\" is null.";

		PDGNode<?> node = this.elementToNodeMap.get(element);
		if (null != node) {
			return node;
		}

		if (element instanceof ExpressionInfo) {
			node = new PDGExpressionNode((ExpressionInfo) element);
		}

		else if (element instanceof StatementInfo) {
			node = new PDGStatementNode((StatementInfo) element);
		}

		else if (element instanceof VariableInfo) {
			node = new PDGParameterNode((VariableInfo) element);
		}

		else {
			assert false : "\"element\" is an invalid parameter.";
		}

		this.elementToNodeMap.put(element, node);

		return node;
	}

	public SortedSet<PDGNode<?>> getAllNodes() {
		final SortedSet<PDGNode<?>> nodes = new TreeSet<PDGNode<?>>();
		nodes.addAll(this.elementToNodeMap.values());
		return nodes;
	}

	public int size() {
		return this.elementToNodeMap.size();
	}
}
