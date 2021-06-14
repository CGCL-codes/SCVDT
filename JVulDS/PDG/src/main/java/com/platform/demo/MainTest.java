package com.platform.demo;

import com.platform.demo.service.PdgService;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class MainTest {
    public static void main(String[] args) throws IOException {
        //unzip("folder.zip");
//        CFGService cfgService = new CFGService();
//        HttpServletResponse response = null;
//        cfgService.toJsonCfg("/Users/ke/Documents/snail/graduate/platform/serverTest/1/CVE-2014-3576_00921f2_TransportConnection.java", response);
//        FileOutputStream fos1 = new FileOutputStream(new File(Config.uploadBasePath + File.separator + "folder.zip"));
//        toZip(Config.uploadBasePath + File.separator + "folder", fos1,true);
//        CFGService cfgService = new CFGService();
//        cfgService.toJsonCfg(null, null);


        PdgService pdgService = new PdgService();
        pdgService.addPDGNode("/Users/ke/Documents/snail/graduate/platform/serverTest/Java_gitlab/DLDetect/test");
    }

    public static void unzip(String fileName){

        String suffixName = fileName.substring(fileName.indexOf("."));
        String filePath = Config.uploadBasePath + File.separator;
        //System.out.println(filePath);

        String command = "";
        switch (suffixName){
            case ".tar":
                command += "tar -xvf " +  filePath + fileName + " -C " + filePath + "/";
                break;
            case ".tgz":
                command += "tar -zxvf " + filePath + fileName  + " -C " + filePath + "/";
                break;
            case ".gz":
                //判断是否是.tar.gz
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
                //判断是否是.tar.xz
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

    public static void doCmd(String command){
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

    public static void toZip(String srcDir, OutputStream out, boolean KeepDirStructure)

        throws RuntimeException{


        long start = System.currentTimeMillis();

        ZipOutputStream zos = null ;

        try {

            zos = new ZipOutputStream(out);

            File sourceFile = new File(srcDir);

            compress(sourceFile,zos,sourceFile.getName(),KeepDirStructure);

            long end = System.currentTimeMillis();

            System.out.println("压缩完成，耗时：" + (end - start) +" ms");

        } catch (Exception e) {

            throw new RuntimeException("zip error from ZipUtils",e);

        }finally{

            if(zos != null){

                try {

                    zos.close();

                } catch (IOException e) {

                    e.printStackTrace();

                }

            }

        }

    }
    /**
     94
     * 递归压缩方法
     95
     * @param sourceFile 源文件
    96
     * @param zos        zip输出流
    97
     * @param name       压缩后的名称
    98
     * @param KeepDirStructure  是否保留原来的目录结构,true:保留目录结构;
    99
     *                          false:所有文件跑到压缩包根目录下(注意：不保留目录结构可能会出现同名文件,会压缩失败)
    100
     * @throws Exception
    101
     */
    private static void compress(File sourceFile, ZipOutputStream zos, String name,
                                 boolean KeepDirStructure) throws Exception{
        final int  BUFFER_SIZE = 2 * 1024;
        byte[] buf = new byte[BUFFER_SIZE];

        if(sourceFile.isFile()){
            // 向zip输出流中添加一个zip实体，构造器中name为zip实体的文件的名字
            zos.putNextEntry(new ZipEntry(name));
            // copy文件到zip输出流中
            int len;
            FileInputStream in = new FileInputStream(sourceFile);
            while ((len = in.read(buf)) != -1){
                zos.write(buf, 0, len);
            }
            // Complete the entry
            zos.closeEntry();
            in.close();
        } else {
            File[] listFiles = sourceFile.listFiles();
            if(listFiles == null || listFiles.length == 0){
                // 需要保留原来的文件结构时,需要对空文件夹进行处理
                if(KeepDirStructure){
                    // 空文件夹的处理
                    zos.putNextEntry(new ZipEntry(name + "/"));
                    // 没有文件，不需要文件的copy
                    zos.closeEntry();
                }

            }else {
                for (File file : listFiles) {
                    // 判断是否需要保留原来的文件结构
                    if (KeepDirStructure) {
                        // 注意：file.getName()前面需要带上父文件夹的名字加一斜杠,
                        // 不然最后压缩包中就不能保留原来的文件结构,即：所有文件都跑到压缩包根目录下了
                        compress(file, zos, name + "/" + file.getName(),KeepDirStructure);
                    } else {
                        compress(file, zos, file.getName(),KeepDirStructure);
                    }



                }

            }

        }

    }

    public static List<File> getFiles(final File file) {

        final List<File> files = new ArrayList<File>();

        if (file.isFile() && file.getName().endsWith(".java")) {
            files.add(file);
        }

        else if (file.isDirectory()) {
            for (final File child : file.listFiles()) {
                final List<File> children = getFiles(child);
                files.addAll(children);
            }
        }

        return files;
    }

    public static void deleteFile(File[] files) {
        for (File file : files){
            if (file.isFile()){
                file.delete();
            }
            else if (file.isDirectory()){
                deleteFile(file.listFiles());
            }
        }
    }

}

