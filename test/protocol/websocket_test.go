package main

import (
	"testing"

	"github.com/gospider007/websocket"
	"github.com/hailsteam/requests"
)

func TestWebSocket(t *testing.T) {
	response, err := requests.Get(nil, "ws://82.157.123.54:9010/ajaxchattest", requests.RequestOption{Headers: map[string]string{
		"Origin": "http://coolaf.com",
	}}) // Send WebSocket request
	if err != nil {
		t.Error(err)
	}
	defer response.CloseBody()
	wsCli := response.WebSocket()
	defer wsCli.Close()
	if err = wsCli.WriteMessage(websocket.TextMessage, "test"); err != nil { // Send text message
		t.Error(err)
	}
	msgType, con, err := wsCli.ReadMessage() // Receive message
	if err != nil {
		t.Error(err)
	}
	if msgType != websocket.TextMessage {
		t.Error("Message type is not text")
	}
	if string(con) != "test" {
		t.Error("Message content is not test")
	}
}
