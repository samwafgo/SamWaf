package model

type MsgPacket struct {
	MsgCode       string        `json:"msg_code"`
	MsgDataPacket MsgDataPacket `json:"msg_data"`
	MsgCmdType    string        `json:"msg_cmd_type"`
}
type MsgDataPacket struct {
	MessageId           string      `json:"message_id"`
	MessageType         string      `json:"message_type"`
	MessageData         string      `json:"message_data"`
	MessageAttach       interface{} `json:"message_attach"`
	MessageDateTime     string      `json:"message_datetime"`
	MessageUnReadStatus bool        `json:"message_unread_status"`
}
