package com.platform.demo.utils;


import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;
import org.apache.commons.compress.utils.IOUtils;

import java.io.*;


public class ZipFiles {
    /**
     * 压缩目录到磁盘zip
     * @throws ZipException
     */
    public static void zipFile() throws ZipException {
        // 生成的压缩文件
        ZipFile zipFile = new ZipFile("C:\\Users\\yckj2494\\Desktop\\a.zip");
        ZipParameters parameters = new ZipParameters();
        // 压缩方式
        parameters.setCompressionMethod(Zip4jConstants.COMP_STORE);
        // 压缩级别
        parameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_FASTEST);
        // 要打包的文件夹
        File currentFile = new File("C:\\Users\\yckj2494\\Desktop\\20210224160154710");
        File[] fs = currentFile.listFiles();
        // 遍历test文件夹下所有的文件、文件夹
        for (File f : fs) {
            if (f.isDirectory()) {
                zipFile.addFolder(f.getPath(), parameters);
            } else {
                zipFile.addFile(f, parameters);
            }
        }
    }

    /**
     * http响应zip
     * @param srcDir
     * @param out
     * @throws ZipException
     * @throws IOException
     */
    public static void zipFile(String srcDir, OutputStream out ) throws ZipException, IOException {
        final long start = System.currentTimeMillis();
        // 要打包的文件夹
        File currentFile = new File(srcDir);
        // 生成的压缩文件
        final File file = new File(srcDir + ".zip");
        ZipFile zipFile = new ZipFile(file);
        ZipParameters parameters = new ZipParameters();
        // 压缩方式
        parameters.setCompressionMethod(Zip4jConstants.COMP_STORE);
        // 压缩级别
        parameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_FASTEST);

        File[] fs = currentFile.listFiles();
        // 遍历test文件夹下所有的文件、文件夹
        for (File f : fs) {
            if (f.isDirectory()) {
                zipFile.addFolder(f.getPath(), parameters);
            } else {
                zipFile.addFile(f, parameters);
            }
        }
        try( InputStream fis = new FileInputStream(zipFile.getFile())) {
            IOUtils.copy(fis, out);
        }
        file.delete();
        //log.info("打包耗时={}ms",System.currentTimeMillis()-start);
    }

    public static void main(String[] args) throws ZipException {
        final long start = System.currentTimeMillis();
        zipFile();
        final long time = System.currentTimeMillis() - start;
        System.out.println("耗时="+time);
    }
}

