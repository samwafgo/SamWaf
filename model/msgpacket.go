package model

type MsgPacket struct {
	Code                string      `json:"code"`
	MessageId           string      `json:"message_id"`
	MessageType         string      `json:"message_type"`
	MessageData         string      `json:"message_data"`
	MessageAttach       interface{} `json:"message_attach"`
	MessageDateTime     string      `json:"message_datetime"`
	MessageUnReadStatus bool        `json:"message_unread_status"`
}
