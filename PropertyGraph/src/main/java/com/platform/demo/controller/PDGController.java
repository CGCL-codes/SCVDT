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


    @GetMapping("/pdgTest")
        public String show(HttpServletResponse response){
            return pdgService.toJson(UserController.path, response);
        }
}
