package com.generatepdg.cfg.node;

import com.generatepdg.cfg.node.CFGPseudoNode.PseudoElement;
import com.generatepdg.pe.ProgramElementInfo;

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
