package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.LSTM;


import org.pytorch.IValue;
import org.pytorch.Module;
import org.pytorch.Tensor;

import java.io.*;
import java.util.*;
public class LSTMPredict {
    private String model_path;
    private String data_dir;
    private Module mod;
    private List<String> _new_frag_list;

    private double[] probability;
    private List<String> cand_list;
    public LSTMPredict() {
        model_path = "/home/user/xyf/jqf-new/fuzz/LSTM/model.pt";
        data_dir = "/home/user/xyf/jqf-new/fuzz/LSTM";
        _new_frag_list = new ArrayList<>();
        probability = null;
        cand_list = new ArrayList<>();
    }



    public String getModel_path() {
        return model_path;
    }

    public String getData_dir() {
        return data_dir;
    }

    public List<String> get_new_frag_list() {
        return _new_frag_list;
    }

    public Module getMod() {
        return mod;
    }

    public double[] getProbability() {
        return probability;
    }

    public List<String> getCand_list() {
        return cand_list;
    }

    public Module load_model() {
        mod = Module.load(getModel_path());
        return mod;
    }

    public void load_data() {
        ProcessBuilder processBuilder = new ProcessBuilder();

        List<String> command = new ArrayList<>();
        command.add("python3");
//        command.add("/home/ubuntu20/Desktop/java-demo/src/main/java/demo/load_data.py");
        command.add("/home/user/xyf/jqf-new/fuzz/src/main/java/edu/berkeley/cs/jqf/fuzz/LM/wxj/demo/LSTM/load_data.py");
        command.add("--data_dir");
        command.add(getData_dir());

        processBuilder.command(command);
        try {

            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                _new_frag_list.add(line);
            }

            int exitVal = process.waitFor();
            if (exitVal != 0) {
                System.out.println("Abnormal!");
                System.exit(0);
                //abnormal...
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public int frag2idx(String frag) {
        return get_new_frag_list().indexOf(frag);
    }

    public Tensor data2LongTensor(long[] batch) {
        return Tensor.fromBlob(batch, new long[]{batch.length});
    }

    public double[] softMax(double[] arr) {
        int length = arr.length;
        double max = arr[length - 1];
        double[] exp_a = new double[arr.length];
        for (int i = 0; i < length; i++) {
            exp_a[i] = Math.pow(Math.E, arr[i] - max);
        }
        double sum = 0;
        for (int i = 0; i < length; i++) {
            sum += exp_a[i];
        }
        double[] result = new double[length];
        for (int i = 0; i < length; i++) {
            result[i] = exp_a[i] / sum;
        }
        return result;
    }

    public void gen_cand(List<String> list) {
        cand_list.clear();//重置
        List<Integer> nodelist = new ArrayList<Integer>();
        for (String node : list) {
            if (frag2idx(node) != -1) {
                nodelist.add(frag2idx(node));
            } else
                continue;
        }
//        System.out.println(nodelist);

        Integer frag = nodelist.get(nodelist.size() - 2);
        List<Integer> pre_seq = nodelist.subList(0, nodelist.size() - 2);

        long[] tmp = new long[pre_seq.size()];
        for (int i = 0; i < pre_seq.size(); i++) {
            tmp[i] = (long) pre_seq.get(i);
        }
        Tensor model_input = data2LongTensor(tmp);
//        System.out.println("input data:");
//        System.out.println(model_input);
//        System.out.println(Arrays.toString(model_input.shape()));
//        System.out.println(Arrays.toString(model_input.getDataAsLongArray()));

        IValue hidden = getMod().runMethod("run_v1", IValue.from(model_input));
//        System.out.println("run_v1:");
//        System.out.println(Arrays.toString(hidden.toTuple()[0].toTensor().shape()));
//        System.out.println(Arrays.toString(hidden.toTuple()[0].toTensor().getDataAsFloatArray()));

        model_input = data2LongTensor(new long[]{frag});
        IValue output = getMod().runMethod("run_v2", IValue.from(model_input), hidden);
//        System.out.println("run_v2:");
//        System.out.println(Arrays.toString(result.toTuple()[0].toTensor().shape()));

        // 预测结果转换为概率
        float[] pro_list = output.toTuple()[0].toTensor().getDataAsFloatArray();
        this.probability = new double[pro_list.length];
        for (int i = 0; i < pro_list.length; i++) {
            probability[i] = (double) pro_list[i];
        }
        this.probability = softMax(probability);

        // 得到候选值
        int[] Index = new int[probability.length];
        Index = FuzzTest.Arraysort(probability);
        for (int idx : Index) {
            this.cand_list.add(_new_frag_list.get(idx));
        }

//        System.out.println(Arrays.toString(probability));
//        System.out.println(cand_list);
    }

    /**
     * 排序并返回对应原始数组的下标
     *
     * @param arr
     * @param desc
     * @return
     */
    public static int[] Arraysort(double[] arr, boolean desc) {
        double temp;
        int index;
        int k = arr.length;
        int[] Index = new int[k];
        for (int i = 0; i < k; i++) {
            Index[i] = i;
        }

        for (int i = 0; i < arr.length; i++) {
            for (int j = 0; j < arr.length - i - 1; j++) {
                if (desc) {
                    if (arr[j] < arr[j + 1]) {
                        temp = arr[j];
                        arr[j] = arr[j + 1];
                        arr[j + 1] = temp;

                        index = Index[j];
                        Index[j] = Index[j + 1];
                        Index[j + 1] = index;
                    }
                } else {
                    if (arr[j] > arr[j + 1]) {
                        temp = arr[j];
                        arr[j] = arr[j + 1];
                        arr[j + 1] = temp;

                        index = Index[j];
                        Index[j] = Index[j + 1];
                        Index[j + 1] = index;
                    }
                }
            }
        }
        return Index;
    }

    /**
     * 排序并返回对应原始数组的下标【默认升序】
     *
     * @param arr
     * @return
     */
    public static int[] Arraysort(double[] arr) {
        return Arraysort(arr, true);
    }
}
