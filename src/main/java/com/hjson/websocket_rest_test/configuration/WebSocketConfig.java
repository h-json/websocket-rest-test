package com.hjson.websocket_rest_test.configuration;

import com.hjson.websocket_rest_test.handler.ConnectWebSocketHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {
    private final ConnectWebSocketHandler connectWebSocketHandler;

    @Autowired
    public WebSocketConfig(ConnectWebSocketHandler connectWebSocketHandler) {
        this.connectWebSocketHandler = connectWebSocketHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(connectWebSocketHandler, "/chat").setAllowedOrigins("*");
    }
}
