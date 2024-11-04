package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

func connectWebSocket(url, token string) error {
	// Create custom header with the auth token
	header := http.Header{}
	header.Add("Sec-WebSocket-Protocol", token)

	// Create dialer with default options
	dialer := websocket.Dialer{
		EnableCompression: true,
	}

	// Connect to WebSocket server
	conn, resp, err := dialer.Dial(url, header)
	if err != nil {
		log.Printf("Dial failed: %v", err)
		if resp != nil {
			log.Printf("HTTP Response Status: %s", resp.Status)
		}
		return err
	}
	defer conn.Close()

	log.Printf("Connected to WebSocket server")

	// Message handling loop
	for {
		// Read message
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			return err
		}

		// Handle text messages (JSON expected)
		if messageType == websocket.TextMessage {
			// Create a map to store the JSON data
			var jsonData map[string]interface{}

			// Unmarshal the JSON message
			if err := json.Unmarshal(message, &jsonData); err != nil {
				log.Printf("JSON parsing error: %v", err)
				// Continue reading messages even if one fails to parse
				continue
			}

			// Print the parsed JSON message
			fmt.Printf("Received message: %+v\n", jsonData)
		}
	}
}
