package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo;

import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.Trees;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class TreeGet {

    //public  TreeNode root = new TreeNode("start",null,null);



    public static TreeNode getTree(ParseTree t, Parser recog){
        //System.out.println(t.getText());
        String[] ruleNames = recog != null ? recog.getRuleNames() : null;
        List<String> ruleNamesList = ruleNames != null ? Arrays.asList(ruleNames) : null;
        //System.out.println(ruleNamesList);
        return  getTree(t,ruleNamesList);
        //System.out.println(Trees.getNodeText(t,ruleNamesList));



    }

    public  static  TreeNode getTree(ParseTree t ,List<String> ruleNames){
//        if(t.getChildCount()==0){
//            //TreeNode treeNode = new TreeNode(Trees.getNodeText(t,ruleNames));
//            return new TreeNode(Trees.getNodeText(t,ruleNames));
//        }
//        else{
//            TreeNode treeNode = new TreeNode(Trees.getNodeText(t,ruleNames));
//            List<TreeNode> children = new ArrayList<>();
//            for(int i = 0;i<t.getChildCount();i++){
//                TreeNode treeNode1 = getTree(t.getChild(i),ruleNames);
//                treeNode1.setParent(treeNode);
//                children.add(treeNode1);
//            }
//            treeNode.setChildren(children);
//
//            return treeNode;
//
//        }
        if(t.getChildCount()==0){
            String name= t.getClass().getSimpleName().replaceAll("Context$", "");
            TreeNode terminal=new TreeNode(name.substring(0,1).toLowerCase(Locale.ROOT)+name.substring(1));
            List<TreeNode> children = new ArrayList<>();
            TreeNode Ctnode = new TreeNode(Trees.getNodeText(t,ruleNames));
            Ctnode.parent=terminal;
            children.add(Ctnode);
            terminal.setChildren(children);
            return terminal;
        }
        else{
            String name= t.getClass().getSimpleName().replaceAll("Context$", "");
            TreeNode treeNode = new TreeNode(name.substring(0,1).toLowerCase(Locale.ROOT)+name.substring(1));
            List<TreeNode> children = new ArrayList<>();
            for(int i = 0;i<t.getChildCount();i++){
                TreeNode treeNode1 = getTree(t.getChild(i),ruleNames);
                treeNode1.setParent(treeNode);
                children.add(treeNode1);
            }
            treeNode.setChildren(children);

            return treeNode;

        }

    }
    public  static  TreeNode TreeCopy(TreeNode root){
        if(root.getChildrenCount()==0){
            //TreeNode treeNode = new TreeNode(Trees.getNodeText(t,ruleNames));
            return new TreeNode(root.statement);
        }
        else{
            TreeNode treeNode = new TreeNode(root.statement);
            List<TreeNode> children = new ArrayList<>();
            for(int i = 0;i<root.getChildrenCount();i++){
                TreeNode treeNode1 = TreeCopy(root.getChildren().get(i));
                treeNode1.setParent(treeNode);
                children.add(treeNode1);
            }
            treeNode.setChildren(children);

            return treeNode;

        }

    }


}
