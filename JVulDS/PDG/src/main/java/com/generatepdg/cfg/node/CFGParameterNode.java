package com.generatepdg.cfg.node;

import com.generatepdg.pe.VariableInfo;

public class CFGParameterNode extends CFGNode<VariableInfo> {

	private CFGParameterNode(final VariableInfo variable) {
		super(variable);
	}
}
