package com.propertygraph.pdg.node;

import com.propertygraph.pe.ProgramElementInfo;

public abstract class PDGNormalNode<T extends ProgramElementInfo> extends
		PDGNode<T> {

	protected PDGNormalNode(final T element) {
		super(element);
	}
}
