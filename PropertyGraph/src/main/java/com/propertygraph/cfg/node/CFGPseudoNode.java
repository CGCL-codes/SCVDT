package com.propertygraph.cfg.node;

import com.propertygraph.cfg.node.CFGPseudoNode.PseudoElement;
import com.propertygraph.pe.ProgramElementInfo;

public class CFGPseudoNode extends CFGNode<PseudoElement> {

	public static class PseudoElement extends ProgramElementInfo {
		PseudoElement() {
			super(0, 0);
		}
	}

	public CFGPseudoNode() {
		super(new PseudoElement());
	}
}
