package websocket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	conn        *websocket.Conn
	config      *Config
	baseURL     string
	handlers    map[string]MessageHandler
	done        chan struct{}
	handlersMux sync.RWMutex
}

type ClientOption func(*Client)

type MessageHandler func(message WSMessage)

// WithBaseURL sets the base URL for the client
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// NewClient creates a new Newt client
func NewClient(newtID, secret string, opts ...ClientOption) (*Client, error) {
	config := &Config{
		NewtID: newtID,
		Secret: secret,
	}

	client := &Client{
		config:   config,
		baseURL:  "http://localhost:3000", // default value
		handlers: make(map[string]MessageHandler),
		done:     make(chan struct{}),
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Load existing config if available
	if err := client.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return client, nil
}

// Connect establishes the WebSocket connection
func (c *Client) Connect() error {
	// Get token for authentication
	token, err := c.getToken()
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Update config with new token and save
	c.config.Token = token
	if err := c.saveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Connect to WebSocket
	wsURL := fmt.Sprintf("ws://%s/ws", c.baseURL[7:]) // Remove http:// prefix
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("failed to parse WebSocket URL: %w", err)
	}

	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.conn = conn
	go c.readPump()

	return nil
}

// Close closes the WebSocket connection
func (c *Client) Close() error {
	close(c.done)
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SendMessage sends a message through the WebSocket connection
func (c *Client) SendMessage(messageType string, data interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg := WSMessage{
		Type: messageType,
		Data: data,
	}

	return c.conn.WriteJSON(msg)
}

// RegisterHandler registers a handler for a specific message type
func (c *Client) RegisterHandler(messageType string, handler MessageHandler) {
	c.handlersMux.Lock()
	defer c.handlersMux.Unlock()
	c.handlers[messageType] = handler
}

// readPump pumps messages from the WebSocket connection
func (c *Client) readPump() {
	defer c.conn.Close()

	for {
		select {
		case <-c.done:
			return
		default:
			var msg WSMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				log.Printf("read error: %v", err)
				return
			}

			c.handlersMux.RLock()
			if handler, ok := c.handlers[msg.Type]; ok {
				handler(msg)
			}
			c.handlersMux.RUnlock()
		}
	}
}

func (c *Client) getToken() (string, error) {
	// If we already have a token, try to use it
	if c.config.Token != "" {
		tokenCheckData := map[string]interface{}{
			"newtId": c.config.NewtID,
			"secret": c.config.Secret,
			"token":  c.config.Token,
		}
		jsonData, _ := json.Marshal(tokenCheckData)

		resp, err := http.Post(c.baseURL+"/auth/newt/get-token", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		var tokenResp TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return "", err
		}

		if tokenResp.Success && tokenResp.Message == "Token session already valid" {
			return c.config.Token, nil
		}
	}

	// Get a new token
	tokenData := map[string]interface{}{
		"newtId": c.config.NewtID,
		"secret": c.config.Secret,
	}
	jsonData, _ := json.Marshal(tokenData)

	resp, err := http.Post(c.baseURL+"/auth/newt/get-token", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	if !tokenResp.Success {
		return "", fmt.Errorf("failed to get token: %s", tokenResp.Message)
	}

	return tokenResp.Data.Token, nil
}
