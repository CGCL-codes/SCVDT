package com.platform.demo.controller;


import com.platform.demo.service.ASTService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
public class ASTController {

    private ASTService astService;

    public ASTController(ASTService astService) {
        this.astService = astService;
    }

    @GetMapping("astTest")
    public String show(HttpServletResponse response){
        return astService.toJson(UserController.path, response);
    }
}
