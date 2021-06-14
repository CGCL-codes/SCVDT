package com.platform.demo.controller;


import com.alibaba.fastjson.JSONObject;
import com.platform.demo.service.PdgService;
//import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;

@RestController
public class PDGController {

    private final PdgService pdgService;

    public PDGController(PdgService pdgService) {
        this.pdgService = pdgService;
    }

    @RequestMapping(value = "/pdg", headers = "Accept=application/json", method = {RequestMethod.POST})
    @ResponseBody
    public void addPDG(@RequestBody JSONObject jsonParam){
        //System.out.println(jsonParam.toString());
        String filePath = jsonParam.get("filePath").toString();
        //System.out.println(filePath);
        pdgService.addPDGNode(filePath);
    }
}
