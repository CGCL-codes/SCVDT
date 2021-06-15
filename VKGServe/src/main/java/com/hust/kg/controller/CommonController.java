package com.hust.kg.controller;

import com.hust.kg.service.CypherService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.OutputStream;

import com.hust.kg.entity.PathConfig;

import javax.servlet.http.HttpServletResponse;

/**
 * @Author wk
 * @Date 2021/03/30 11:43
 * @Description:
 */
@RestController
public class CommonController {
    private final CypherService cypherService;

    public CommonController(CypherService cypherService) {
        this.cypherService = cypherService;
    }

    @RequestMapping(value = "/cypher", method = RequestMethod.POST)
    public String executeCypher(@RequestParam("cypher")String cypher){
        return cypherService.executeCypher(cypher);
    }

    @RequestMapping("upload")
    @ResponseBody
    public String uploadFile(@RequestParam("file") MultipartFile file){
        String fileName = file.getOriginalFilename();
        File dest = new File(PathConfig.uploadBasePath + "/" + fileName);
        // 判断路径是否存在，如果不存在则创建
        if(!dest.getParentFile().exists()) {
            dest.getParentFile().mkdirs();
        }
        try {
            // 保存到服务器中
            file.transferTo(dest);
            return "上传成功";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "上传失败";
    }

    @RequestMapping("download/{fileName}")
    public void download(HttpServletResponse response, @PathVariable String fileName) throws Exception {
        String filePath = PathConfig.downloadPath + "/" + fileName;
        // 文件地址，真实环境是存放在数据库中的
        File file = new File(filePath);
        // 创建输入对象
        FileInputStream fis = new FileInputStream(file);
        // 设置相关格式
        response.setContentType("application/force-download");
        // 设置下载后的文件名以及header
        response.addHeader("Content-disposition", "attachment;fileName=" + fileName);
        // 创建输出对象
        OutputStream os = response.getOutputStream();
        // 常规操作
        byte[] buf = new byte[1024];
        int len = 0;
        while((len = fis.read(buf)) != -1) {
            os.write(buf, 0, len);
        }
        fis.close();
    }

    @RequestMapping("downloadJson")
    public void downloadJson(HttpServletResponse response) throws Exception {
        String filePath = PathConfig.downloadPath + "/cypher-data.json";
        // 文件地址，真实环境是存放在数据库中的
        File file = new File(filePath);
        // 创建输入对象
        FileInputStream fis = new FileInputStream(file);
        // 设置相关格式
        response.setContentType("application/force-download");
        // 设置下载后的文件名以及header
        response.addHeader("Content-disposition", "attachment;fileName=cypher-data.json");
        // 创建输出对象
        OutputStream os = response.getOutputStream();
        // 常规操作
        byte[] buf = new byte[1024];
        int len = 0;
        while((len = fis.read(buf)) != -1) {
            os.write(buf, 0, len);
        }
        fis.close();
    }
}
