package model

type GptMessage struct {
	Content     string `json:"content"`
	Role        string `json:"role"`
	Unimportant bool   `json:"unimportant"`
}

type GptResponseFormat struct {
	Type string `json:"type"`
}
type GPTRequest struct {
	Messages         []GptMessage      `json:"messages"`
	Model            string            `json:"model"`
	FrequencyPenalty float64           `json:"frequency_penalty"`
	MaxTokens        int               `json:"max_tokens"`
	PresencePenalty  float64           `json:"presence_penalty"`
	ResponseFormat   GptResponseFormat `json:"response_format"`
	Stop             interface{}       `json:"stop"`
	Stream           bool              `json:"stream"`
	Temperature      float64           `json:"temperature"`
	TopP             float64           `json:"top_p"`
}
