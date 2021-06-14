package com.snail.dldetectvul.run;


import com.alibaba.fastjson.JSONObject;
import com.snail.dldetectvul.Config;
import com.snail.dldetectvul.entity.Flaw;

import com.snail.dldetectvul.utils.HttpUtils;
import org.apache.commons.cli.*;

import java.io.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;


/**
 * @author HuangJiao
 * @date 2021-05-13
 */
public class VulDeePackerStaticService {
    private static String projPath;

    public static String project;
    public static void main(String[] args){
        final Options options = new Options();

        {
            final Option d = new Option("d", "directory", true,
                    "target directory");
            d.setArgName("directory");
            d.setArgs(1);
            d.setRequired(true);
            options.addOption(d);
        }

        final CommandLineParser parser = new PosixParser();
        final CommandLine cmd;
        try {
            cmd = parser.parse(options, args);
            final File target = new File(cmd.getOptionValue("d"));

            if (!target.exists()) {
                System.err
                        .println("specified directory or file does not exist.");
                System.exit(0);
            }
            project = cmd.getOptionValue("d");
            run(target.getName());
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    public static List<Flaw> run(String projectName) {

        System.out.println("start deep learning detect.");
        List<Flaw> flaws = new ArrayList<>();

        JSONObject json = new JSONObject();
        json.put("filePath", project);

        String result = HttpUtils.doPost(Config.fileServiceUrl, json.toString());//result  就是结果

         //3.获取结果
        detectVul(projectName);

        // 4. 返回flaw
       // flaws = getFlawsByDL();

        System.out.println("end deep learning detect.");
        return flaws;
    }

    private static List<Flaw> getFlawsByDL() {
        return null;
    }

    private static void detectVul(String projectName) {
        File file = new File(Config.fixedFilePath + File.separator + "softwareTempFiles" + File.separator + projectName);
        if (!file.exists()){
            file.mkdirs();
        }
        else {
            if (file.listFiles() != null){
                deleteFile(file.listFiles());
            }
        }
        projPath = Config.fixedFilePath + File.separator + "softwareTempFiles" + File.separator + projectName;
        File projFile = new File(projPath);

        if (!projFile.exists()){
            projFile.mkdirs();
        }

        String slicePath = projFile.getAbsolutePath() + File.separator + "slice";
        String corpusPath = projFile.getAbsolutePath() + File.separator + "corpus";
        String vectorPath = projFile.getAbsolutePath() + File.separator + "vector";
        String dlCorpusPath = projFile.getAbsolutePath() + File.separator + "dlCorpus";

        File slice = new File(slicePath);
        if (!slice.exists()){
            slice.mkdirs();
        }
        File corpus = new File(corpusPath);
        if (!corpus.exists()){
            corpus.mkdirs();
        }
        File vector = new File(vectorPath);
        if (!vector.exists()){
            vector.mkdirs();
        }

        File dlCorpus = new File(dlCorpusPath);
        if (!dlCorpus.exists()){
            dlCorpus.mkdirs();
        }

        String pythonFiles = Config.fixedFilePath + File.separator + "execFiles" + File.separator;
        //System.out.println(pythonFiles);
        String[] cmd = {Config.pythonEnvPath, pythonFiles + "detectVul.py", projPath, Config.fixedFilePath};
        int status = exeuteCmd(cmd, null, new File(pythonFiles));
        if (status != 0){
            System.err.println("execute python fail");
        }
    }

    //以表格的结果输出 重新写
    public static List<Flaw> getFlawsByDL(String codeType){
        List<Flaw> flaws = new ArrayList<>();

        String result = projPath + File.separator + "result.txt";
        File file = new File(result);
        if (!file.exists()){
            return flaws;
        }
        try {
            FileInputStream fin = new FileInputStream(result);
            InputStreamReader reader = new InputStreamReader(fin);
            BufferedReader buffReader = new BufferedReader(reader);
            String strTmp = "";
            while ((strTmp = buffReader.readLine()) != null) {
                Flaw flaw = new Flaw();
                System.out.println(strTmp);
                String[] lists = strTmp.split("\\+");
                //if (lists[3].equals("0")) continue;
                int length = 0;
                for (int i = 0; i < lists.length; i++){
                    length += lists[i].length();
                    if (i == 0){
                        String filename = lists[i];
                        String[] temp = filename.split(File.separator);
                        flaw.setFilename(temp[temp.length-1]);
                    }
                    else if (i == 1){
                        flaw.setLine(Integer.parseInt(lists[i]));
                    }
                    else if (i == 2){
                        if ("AE".equals(lists[i])){
                            flaw.setCategory("Arithmetic expression");
                        }
                        else if ("MI".equals(lists[i])){
                            flaw.setCategory("Library/API function");
                        }
                        else if ("SE".equals(lists[i])){
                            flaw.setCategory("Sensitive exposure");
                        }
                        else flaw.setCategory("Null");
                    }
                    else if (i == 4){
                        flaw.setFunName(lists[i]); //函数 补充
                        break;
                    }
                }
                length += 4;
                String context = strTmp.substring(length+1);
                System.out.println(context);
                flaw.setContext(context);
                flaw.setColumn("1");
                flaw.setLevel("1");
                flaw.setWarning("Null");
                flaw.setSuggestion("Null");
                flaw.setCwes("Null");
                BigDecimal reliability = new BigDecimal(100.00);
                flaw.setReliability(reliability);
                flaw.setCodeType(codeType);
                flaws.add(flaw);
            }
            buffReader.close();
            reader.close();
            fin.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return flaws;
    }

    // 删除所有的文件
    private static void deleteFile(File[] files) {
        for (File file : files){
            if (file.isFile()){
                file.delete();
            }
            else if (file.isDirectory()){
                deleteFile(file.listFiles());
            }
        }
    }

    private static int exeuteCmd(String[] cmd, String[] envp, File dir){
        try {
            Process proc = Runtime.getRuntime().exec(cmd, envp, dir);
            BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line = null;
            //System.out.println("python output：");
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
            in.close();
            int status = 0;
            status = proc.waitFor();
            proc.destroy();
            return status;
        } catch (IOException e) {
            e.printStackTrace();
        }catch (InterruptedException e) {
            e.printStackTrace();
        }
        return -1;
    }
}
