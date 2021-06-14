package com.generatepdg.cfg.node;

import com.generatepdg.pe.ProgramElementInfo;

public class CFGNormalNode<T extends ProgramElementInfo> extends CFGNode<T> {

	public CFGNormalNode(final T element) {
		super(element);
	}
}
