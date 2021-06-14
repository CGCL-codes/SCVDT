package com.propertygraph.cfg.node;

import com.propertygraph.pe.ProgramElementInfo;

public class CFGNormalNode<T extends ProgramElementInfo> extends CFGNode<T> {

	public CFGNormalNode(final T element) {
		super(element);
	}
}
