package websocket

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func getConfigPath() string {
	var configDir string
	switch runtime.GOOS {
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "newt-client")
	case "windows":
		configDir = filepath.Join(os.Getenv("APPDATA"), "newt-client")
	default: // linux and others
		configDir = filepath.Join(os.Getenv("HOME"), ".config", "newt-client")
	}

	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Printf("Failed to create config directory: %v", err)
	}

	return filepath.Join(configDir, "config.json")
}

func (c *Client) loadConfig() error {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// Only update token from saved config
	c.config.Token = config.Token
	return nil
}

func (c *Client) saveConfig() error {
	configPath := getConfigPath()
	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}
