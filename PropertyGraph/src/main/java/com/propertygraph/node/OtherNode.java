package com.propertygraph.node;

public class OtherNode extends PreNode{
    String code;
    String startLine;
    String endLine;

    public void setCode(String code) {
        this.code = code;
    }

    public void setEndLine(String endLine) {
        this.endLine = endLine;
    }

    public void setStartLine(String startLine) {
        this.startLine = startLine;
    }

    public String getCode() {
        return code;
    }

    public String getStartLine() {
        return startLine;
    }

    public String getEndLine() {
        return endLine;
    }
}
