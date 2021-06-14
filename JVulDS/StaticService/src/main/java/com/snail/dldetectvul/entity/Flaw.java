package com.snail.dldetectvul.entity;

import org.springframework.stereotype.Component;

import java.math.BigDecimal;

@Component
public class Flaw {
//    private int id;
    private String codeType;
    //项目名
//    private String name;
    //发现漏洞的文件名
    private String filename;
    //对应的漏洞行
    private int line;
    //对应的漏洞列
    private String column;
    //对应的漏洞等级
    private String level;
    //对应的漏洞类型
    private String category;
    //发生漏洞的方法名或变量名
    private String funName;
    //漏洞描述
    private String warning;
    //漏洞修复建议
    private String suggestion;

    private BigDecimal reliability;

    public String getCodeType() {
        return codeType;
    }

    public void setCodeType(String codeType) {
        this.codeType = codeType;
    }

    //漏洞对应的cwe
    private String cwes;
    //漏洞发生的代码
    private String context;

//    public String getName() {
//        return name;
//    }
//
//    public void setName(String name) {
//        this.name = name;
//    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public int getLine() {
        return line;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public String getColumn() {
        return column;
    }

    public void setColumn(String column) {
        this.column = column;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getFunName() {
        return funName;
    }

    public void setFunName(String funName) {
        this.funName = funName;
    }

    public String getWarning() {
        return warning;
    }

    public void setWarning(String warning) {
        this.warning = warning;
    }

    public String getSuggestion() {
        return suggestion;
    }

    public void setSuggestion(String suggestion) {
        this.suggestion = suggestion;
    }

    public String getCwes() {
        return cwes;
    }

    public void setCwes(String cwes) {
        this.cwes = cwes;
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public void setReliability(BigDecimal reliability) {
        this.reliability = reliability;
    }

    public BigDecimal getReliability() {
        return reliability;
    }

    public void setAll(String codeType, String filename, int line, String column, String level, String category, String funName, String warning, String suggestion, String cwes, String context, BigDecimal reliability){
        this.codeType = codeType;
        this.filename = filename;
        this.line = line;
        this.column = column;
        this.level = level;
        this.category = category;
        this.funName = funName;
        this.warning = warning;
        this.suggestion = suggestion;
        this.cwes =cwes;
        this.context = context;
        this.reliability = reliability;
    }

    @Override
    public String toString() {
        return "Flaw{" +
                "codeType='" + codeType + '\'' +
                ", filename='" + filename + '\'' +
                ", line=" + line +
                ", column='" + column + '\'' +
                ", level=" + level + '\'' +
                ", category='" + category + '\'' +
                ", funName='" + funName + '\'' +
                ", warning='" + warning + '\'' +
                ", suggestion='" + suggestion + '\'' +
                ", cwes='" + cwes + '\'' +
                ", context='" + context + '\'' +
                ", reliability='" + reliability + '\'' +
                '}';
    }
}
