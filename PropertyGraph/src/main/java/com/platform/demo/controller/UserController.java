package com.platform.demo.controller;


import com.platform.demo.Config;
import com.platform.demo.service.Common;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.List;

@RestController
public class UserController {
    public static String path;


    @RequestMapping("/upload")
    @ResponseBody
    public String uploadFile(MultipartFile file){

        String fileName = file.getOriginalFilename();
        if (!fileName.endsWith(".java")){
            path = Config.uploadBasePath + File.separator + fileName.substring(0, fileName.indexOf("."));
        }
        else path = Config.uploadBasePath + File.separator + fileName;
        File dest = new File(Config.uploadBasePath + File.separator + fileName);
       
        if(!dest.getParentFile().exists()) {
            dest.getParentFile().mkdirs();
        }
        else{
            for (File f : dest.getParentFile().listFiles()){
                f.delete();
            }
        }

        try {
           
            file.transferTo(dest);

            
            if (!fileName.endsWith(".java")) {
                unzip(fileName);
            }
            return "上传成功";
        } catch (Exception e) {
            e.printStackTrace();
        }
        //UserController.dest = dest;
        return "upload fail";
    }

    public  void unzip(String fileName){

        String suffixName = fileName.substring(fileName.indexOf("."));
        String filePath = Config.uploadBasePath + File.separator;
      

        String command = "";
        switch (suffixName){
            case ".tar":
                command += "tar -xvf " +  filePath + fileName + " -C " + filePath + "/";
                break;
            case ".tgz":
                command += "tar -zxvf " + filePath + fileName  + " -C " + filePath + "/";
                break;
            case ".gz":
                
                System.out.println(fileName);
                String[] values = fileName.split("\\.");
//                for(String value:values){
//                    System.out.println(value);
//                }
                if(values.length > 1 && values[values.length - 2].equals("tar"))
                    command += "tar -zxvf " + filePath + fileName + " -C " + filePath;
                else
                    command += "gunzip " + filePath + fileName;
                break;
            case ".xz":
                
                System.out.println(fileName);
                String[] values2 = fileName.split("\\.");
//                for(String value:values){
//                    System.out.println(value);
//                }
                if(values2.length > 1 && values2[values2.length - 2].equals("tar"))
                    command += "tar xvJf " + filePath + fileName + " -C " + filePath;
                else
                    command += "xz -d " + filePath + fileName;
                break;
            case ".zip":
                command += "unzip " + filePath + fileName + " -d " + filePath;
                break;
            case ".rar":
                command += "rar x " + filePath + fileName + " -d " + filePath;
                break;

        }

        System.out.println(command);
        doCmd(command);
    }

    public void doCmd(String command){
        StringBuilder buf = new StringBuilder(1000);
        String rt="-1";
        String[] cmd = {"sh","-c",command};
        try {
            Process pos = Runtime.getRuntime().exec(cmd);

            InputStreamReader ir = new InputStreamReader(pos.getInputStream());
            LineNumberReader input = new LineNumberReader(ir);
            String ln="";
            while ((ln =input.readLine()) != null) {
                buf.append(ln).append("<br>");
                System.out.println(ln);
            }
            int status = pos.waitFor();
            System.out.println("status: "+ status);
            System.out.println(pos.exitValue());
            rt = buf.toString();
            input.close();
            ir.close();

        } catch (java.io.IOException e) {
            rt=e.toString();
        }catch (Exception e) {
            System.out.println(e.toString());
        }
//        System.out.println(rt);
    }
  
    @RequestMapping("download/")
    public String download(HttpServletResponse response) throws Exception {
        //String filePath = "/home/wk/fuzzing_test/software/upload/" + fileName;
        final List<File> list = Common.getFiles(new File(Config.uploadBasePath + File.separator + "dot"));
        if (list.size() == 0 || list == null){
            return "先生成树或者图";
        }

        for (final File file : list) {
           
            FileInputStream fis = new FileInputStream(file);
           
            response.setContentType("application/force-download");
           
            response.addHeader("Content-disposition", "attachment;fileName=" + file.getName());
           
            OutputStream os = response.getOutputStream();
           
            byte[] buf = new byte[1024];
            int len = 0;
            while ((len = fis.read(buf)) != -1) {
                os.write(buf, 0, len);
            }
            fis.close();
        }
        return "success";
    }

}
