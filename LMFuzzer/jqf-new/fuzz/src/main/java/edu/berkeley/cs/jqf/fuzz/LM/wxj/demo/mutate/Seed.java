package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.mutate;

import edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.TreeNode;

import java.util.*;

public class Seed {

    public  int   id;
    public  int   parentId;
    public  TreeNode root;
    public  TreeNode lastUpdate;
    public int fuzzCount;
    public HashSet<String> identifier = new HashSet<>();
    public HashMap<String,List<TreeNode>> StatementIndexTreeNode = new HashMap<>();

    public PriorityQueue<TreeNode> Candidate = new PriorityQueue<TreeNode>(new Comparator<TreeNode>() {
        @Override
        public int compare(TreeNode o1, TreeNode o2) {
            return Double.compare(o1.probability,o2.probability);

        }
    });


    public Seed(TreeNode root){
        this.root = root;
    }

    public TreeNode getRoot() {
        return root;
    }

    public TreeNode getLastUpdate() {
        return lastUpdate;
    }

    public int getFuzzCount() {
        return fuzzCount;
    }

    public void setRoot(TreeNode root) {
        this.root = root;
    }
}
