package com.hust.kg.entity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * @Author wk
 * @Date 2021/04/01 15:46
 * @Description:
 */
@Configuration
public class CrossConfig {
    private CorsConfiguration buildConfig() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.addAllowedOrigin("*"); //允许任何域名

        corsConfiguration.addAllowedHeader("*"); //允许任何头

        corsConfiguration.addAllowedMethod("*"); //允许任何方法

        return corsConfiguration;

    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", buildConfig()); //注册

        return new CorsFilter(source);

    }
}
