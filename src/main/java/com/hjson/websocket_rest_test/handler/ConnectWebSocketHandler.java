package com.hjson.websocket_rest_test.handler;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.HashSet;
import java.util.Set;

@Component
public class ConnectWebSocketHandler extends TextWebSocketHandler {
    private final Set<WebSocketSession> sessions = new HashSet<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        sessions.add(session);
        for(WebSocketSession client : sessions) {
            if(client.isOpen()) {
                client.sendMessage(new TextMessage(session.getId() + "님이 참여하였습니다. 총 " + sessions.size() + "명"));
            }
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus closeStatus) throws Exception {
        sessions.remove(session);
        for(WebSocketSession client : sessions) {
            if(client.isOpen()) {
                client.sendMessage(new TextMessage(session.getId() + "님이 나갔습니다. 총 " + sessions.size() + "명"));
            }
        }
    }

    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage textMessage) throws Exception {
        for(WebSocketSession client : sessions) {
            if(client.isOpen()) {
                client.sendMessage(textMessage);
            }
        }
    }
}
