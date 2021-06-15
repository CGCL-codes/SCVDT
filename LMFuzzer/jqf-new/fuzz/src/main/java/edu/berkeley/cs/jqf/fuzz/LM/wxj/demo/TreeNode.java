package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo;

//import org.antlr.v4.runtime.tree.Tree;

import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.ngram.Model;
import org.python.antlr.ast.Str;

import java.util.*;

public class TreeNode {

    public String  statement  ;

    public TreeNode parent;

    public List<TreeNode> children = new ArrayList<>();

    private List<List<TreeNode>> allPath = new ArrayList<>();

    private List<TreeNode> allNode = new ArrayList<>();

    private List<TreeNode> statementNode = new ArrayList<>();

    private List<TreeNode> Ngram3Node = new ArrayList<>();

    private Set<String> allStatement = new HashSet<>();

    private StringBuilder sb = new StringBuilder();

    public  double probability;

    public int fuzzCount;


    public TreeNode(String statement) {
        this.statement = statement;
    }

    public TreeNode(String statement, TreeNode parent, List<TreeNode> children) {
        this.statement = statement;
        this.parent = parent;
        this.children = children;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TreeNode treeNode = (TreeNode) o;
        return Objects.equals(statement, treeNode.statement) &&
                Objects.equals(parent, treeNode.parent) &&
                Objects.equals(children, treeNode.children);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statement, parent, children);
    }


    @Override
    public String toString() {
//        return "TreeNode{" +
//                "statement='" + statement + '\'' +
//                '}';
        return statement + "     " + probability;
        //return
    }

    public TreeNode getParent() {
        return parent;
    }

    public List<TreeNode> getChildren() {
        return children;
    }

    public String getStatement() {
        return statement;
    }

    public double getProbability(){return  probability;}

    public int getFuzzCount(){return  fuzzCount;}

    public void setStatement(String statement) {
        this.statement = statement;
    }

    public void setChildren(List<TreeNode> children) {
        this.children = children;
    }


    public void setParent(TreeNode parent) {
        this.parent = parent;
    }

    public void setProbability(double probability){this.probability = probability;}

    public void setFuzzCount(int fuzzCount){
        this.fuzzCount = fuzzCount;
    }

    public int getChildrenCount(){
        return children.size();
    }
    //得到从该节点遍历的text
    public String gettext(){
        if(this.getChildrenCount()==0){
            if(!"<EOF>".equals(this.getStatement()))
                return this.getStatement();
            else
                return "";
        }
        else{
            StringBuilder builder = new StringBuilder();
            for(int i = 0; i<this.getChildrenCount(); i++){
                if (i > 0) {

                    builder.append(" ");
                }
                TreeNode child = this.getChildren().get(i);
                builder.append(child.gettext());
            }
            return builder.toString();
        }
    }



//    public String getString(){
//
//    }




    //获得祖先结点
    public List<TreeNode> getAncestor(TreeNode treeNode){
        if (treeNode.getParent() == null) {
            return Collections.emptyList();
        } else {
            List<TreeNode> ancestors = new ArrayList<>();

            for(treeNode = treeNode.getParent(); treeNode!= null; treeNode = treeNode.getParent()) {
                ancestors.add(0,treeNode);
            }

            return ancestors;
        }
    }

    public List<String> getAncestorSequence(TreeNode treeNode){
        ArrayList<String> res = new ArrayList();
        List<TreeNode> list = new ArrayList<>();

        list=  getAncestor(treeNode);

        for(TreeNode temp : list){
            res.add(temp.getStatement());
        }
        return res;


    }

    public  String getNgram(int n){
        TreeNode treeNode = this;
        String ngram = treeNode.getStatement();
        for(int i = 0 ;i< n-1;i++){
            if(treeNode.getParent() == null){
                break;
            }
            else{
                treeNode = treeNode.getParent();
                ngram = treeNode.getStatement() + " "+ ngram;
            }
        }
        return ngram;
    }




    public double getNodeProbability(Model Model, int n){
        return Model.getProbability(this.getNgram(n),n);
    }





    public List<TreeNode> getAllNode() {
        if(allNode.size()!=0)
            return allNode;
        else
            return  transAllNode(this);

    }

    public List<TreeNode> transAllNode(TreeNode treeNode){

        if(treeNode!=null && treeNode.getChildrenCount()!=0){
            allNode.add(treeNode);
            if(treeNode.getChildrenCount()!=0){
                for (int i = 0; i <treeNode.getChildrenCount(); i++) {
                    transAllNode(treeNode.getChildren().get(i));
                }
            }
        }
        return allNode;
    }

    public Set<String> getAllStatement() {
        if(allStatement.size()!=0)
            return allStatement;
        else
            return  transAllStatement(this);

    }

    public Set<String> transAllStatement(TreeNode treeNode){
        if(treeNode!=null && treeNode.getChildrenCount()!=0){
            allStatement.add(treeNode.getStatement());
            if(treeNode.getChildrenCount()!=0){
                for (int i = 0; i <treeNode.getChildrenCount(); i++) {
                    transAllStatement(treeNode.getChildren().get(i));
                }
            }
        }
        return allStatement;

    }

    public  List<TreeNode> getStatementNodeList(String statement){
        statementNode.clear();
        transStatement(this,statement);
        return statementNode;
    }

    public void transStatement(TreeNode treeNode, String statement){
        if(treeNode!=null){

            if(treeNode.getStatement().equals(statement))
                statementNode.add(treeNode);
            if(treeNode.getChildrenCount()!=0){
                for (int i = 0; i <treeNode.getChildrenCount(); i++) {
                    transStatement(treeNode.getChildren().get(i),statement);
                }
            }
        }
        return ;
    }

    public void transNgram3(TreeNode treeNode,String string1,String string2){
        if(treeNode!=null){

            if(treeNode.getStatement().equals(string1)){
                if(treeNode.getChildrenCount()!=0){
                    for(int i = 0 ;i<treeNode.getChildrenCount();i++){
                        TreeNode temp1 = treeNode.getChildren().get(i);
                        if(temp1.getStatement().equals(string2)){
                            if(temp1.getChildrenCount()!=0){
                                for(int j = 0 ; j<temp1.getChildrenCount();j++){
                                    Ngram3Node.add(temp1.getChildren().get(j));
                                }
                            }
                        }
                    }
                }
            }
            if(treeNode.getChildrenCount()!=0){
                for (int i = 0; i <treeNode.getChildrenCount(); i++) {
                    transNgram3(treeNode.getChildren().get(i),string1,string2);
                }
            }
        }
        return ;
    }
    public List<TreeNode> getNgram3Node(String string1 ,String string2){
        Ngram3Node.clear();
        transNgram3(this,string1,string2);
        return Ngram3Node;
    }

    public List<List<TreeNode>> getPath(TreeNode treeNode){

        if(treeNode.getChildrenCount()==0){
            List<TreeNode> path = treeNode.getAncestor(treeNode);
            path.add(treeNode);
            allPath.add(path);
        }
        else {
            for(int i = 0; i<treeNode.getChildrenCount(); i++){
                getPath(treeNode.getChildren().get(i));
            }
        }
        return allPath;
    }

}
