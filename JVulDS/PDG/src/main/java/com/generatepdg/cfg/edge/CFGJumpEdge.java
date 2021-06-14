package com.generatepdg.cfg.edge;

import com.generatepdg.cfg.node.CFGNode;

public class CFGJumpEdge extends CFGEdge {

	CFGJumpEdge(final CFGNode<?> fromNode, final CFGNode<?> toNode) {
		super(fromNode, toNode);
	}

	@Override
	public String getDependenceTypeString() {
		return "jump";
	}

	@Override
	public String getDependenceString() {
		return "jump";
	}
}
