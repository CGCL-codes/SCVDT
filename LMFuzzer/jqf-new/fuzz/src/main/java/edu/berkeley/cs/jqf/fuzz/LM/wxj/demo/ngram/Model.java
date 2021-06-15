package edu.berkeley.cs.jqf.fuzz.LM.wxj.demo.ngram;

import java.io.*;
import java.util.HashMap;

public class Model {

    public long one_gram_count ;
    public long two_gram_count;
    public long three_gram_count;

    public HashMap<String,Double> oneGram = new HashMap<>();
    public HashMap<String,Double> twoGram = new HashMap<>();
    public HashMap<String,Double> threeGram = new HashMap<>();
    //public HashMap<String, List<String>> thetwo = new HashMap<>();
    public FileReader arpa;

    public Model(FileReader fileReader) {
        this.arpa = fileReader;
        this.calculate();
    }

    public void calculate(){
        BufferedReader reader = new BufferedReader(this.arpa);

        int linecount = 0;

        try {
            String x;
            while ((x = reader.readLine())!=null){
                linecount++;
                if(linecount>=5&&linecount<=7){
                    //System.out.println(x);
                    String[] result =  x.split("=");
                    switch (linecount){
                        case  5 : one_gram_count = Long.parseLong(result[1]);
                        case  6 : two_gram_count = Long.parseLong(result[1]);
                        case  7:  three_gram_count = Long.parseLong(result[1]);
                    }

                }
                else if(linecount>=10 && linecount<=(10+one_gram_count-1)){
                    //System.out.println(x);

                    String[] result = x.split("\\s+");
                    //System.out.println(result.length);
                    //System.out.println(result[1] + "   " + Double.valueOf(result[0]));
                    oneGram.put(result[1],Double.valueOf(result[0]));

                }
                else if(linecount>= (10 + 2 + one_gram_count) && linecount<=(10 + 2 +one_gram_count + two_gram_count -1)){
                    //System.out.println(x);

                    String[] result = x.split("\\s+");
                    String two = result[1] + " " + result[2];
                    twoGram.put(two,Double.valueOf(result[0]));
                }
                else if(linecount>=(10 + 2 +one_gram_count + two_gram_count+2) &&linecount<=(10 + 2 +one_gram_count + two_gram_count+2 +three_gram_count-1)){
                    String[] result = x.split("\\s+");
                    String three = result[1] + " " + result[2] + " " +result[3];
                    threeGram.put(three,Double.valueOf(result[0]));
                }
                //System.out.println(x);
            }
            System.out.println("one gram " + one_gram_count);
            System.out.println("two gram " + two_gram_count);
            System.out.println("three gram " + three_gram_count);
            System.out.println("one gram hashmap " + oneGram.size());
            System.out.println(oneGram);
            System.out.println("two gram hashmap " + twoGram.size());
            System.out.println(twoGram);
            System.out.println("three gram hashmap " + threeGram.size());
            System.out.println(threeGram);


        }
        catch (Exception e){
            e.printStackTrace();
        }

    }

    public double getProbability(String ngram ,int n){
        switch (n){
            case 1: return oneGram.get(ngram)!= null? oneGram.get(ngram):Double.MIN_EXPONENT;
            case 2: return twoGram.get(ngram)!=null? twoGram.get(ngram):Double.MIN_EXPONENT;
            case 3: return threeGram.get(ngram)!=null? threeGram.get(ngram):Double.MIN_EXPONENT;
            default: return Double.MIN_EXPONENT;
        }
    }
}
