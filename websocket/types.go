package websocket

type Config struct {
	NewtID string `json:"newtId"`
	Secret string `json:"secret"`
	Token  string `json:"token"`
}

type TokenResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}
