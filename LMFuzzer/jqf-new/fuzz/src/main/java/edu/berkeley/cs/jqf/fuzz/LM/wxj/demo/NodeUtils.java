package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo;



import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.ngram.Model;

import java.util.ArrayList;


import java.util.Comparator;
import java.util.List;
import java.util.PriorityQueue;

public class NodeUtils {


    public static  List<TreeNode> getMaxProbabilityNode(TreeNode root, Model Model, int n){

        List<TreeNode> allNode = root.getAllNode();
        System.out.println(allNode.size());

        allNode.sort((o1, o2) -> Double.compare(o2.getNodeProbability(Model, n), o1.getNodeProbability(Model, n)));

        double maxProbability = allNode.get(0).getNodeProbability(Model,n);
        List<TreeNode> MaxNodeList = new ArrayList<>();
        for (TreeNode i : allNode){
            if(i.getNodeProbability(Model,n)==maxProbability)
                MaxNodeList.add(i);
            else
                break;
        }
        return MaxNodeList;
    }

    public static PriorityQueue<TreeNode> getPriorityQueue(TreeNode root , Model model ,int n){

        List<TreeNode> allNode = root.getAllNode();
        PriorityQueue<TreeNode> queue = new PriorityQueue<>(new Comparator<TreeNode>() {
            @Override
            public int compare(TreeNode o1, TreeNode o2) {
                if (o2.getNodeProbability(model, n) > o1.getNodeProbability(model, n))
                    return 1;
                else if (o2.getNodeProbability(model, n) == o1.getNodeProbability(model, n))
                    return 0;
                else
                    return -1;
            }
        });

        System.out.println(allNode.size());
        for(TreeNode i : allNode){
            queue.add(i);
        }
        return  queue;
    }




//    public static List<TreeNode> getPrepareNode(TreeNode root,String ngram,int n){
//        List<TreeNode> result = new ArrayList<>();
//        if(n == 3){
//            System.out.println("ngram is "+ ngram);
//            String[] strings = ngram.split("\\s+");
//            String string1 = strings[0];
//            String string2 = strings[1];
//            System.out.println("String1  String2 is  "+ string1 +"       " +string2);
//
//            result = root.getNgram3Node(string1,string2);
//        }
//        return  result;
//
//    }



    public  static  void replace(TreeNode Node1,TreeNode Node2 ){
        TreeNode parent = Node1.getParent();
        for(int i = 0; i<parent.getChildrenCount(); i++){
            if(parent.getChildren().get(i) == Node1){
                parent.getChildren().set(i,Node2);
                Node2.setParent(parent);
            }
        }
        Node1.setParent(null);
    }
    public  static  void  recover(TreeNode Node1 ,TreeNode Node2){
        TreeNode parent = Node1.getParent();
        for(int i = 0; i<parent.getChildrenCount(); i++){
            if(parent.getChildren().get(i) == Node1){
                parent.getChildren().set(i,Node2);
                Node2.setParent(parent);
            }
        }
        Node1.setParent(null);
    }
}
