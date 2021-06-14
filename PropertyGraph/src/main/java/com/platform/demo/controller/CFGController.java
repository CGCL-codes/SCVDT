package com.platform.demo.controller;

import com.platform.demo.service.ASTService;
import com.platform.demo.service.CFGService;
import com.platform.demo.service.PdgService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

@RestController
public class CFGController {

    private final CFGService cfgService;

    public CFGController(CFGService cfgService) {
        this.cfgService = cfgService;
    }

    @GetMapping("/cfgTest")
    public String show(HttpServletResponse response) throws IOException {
        return cfgService.toJsonCfg(UserController.path, response);
    }

}
