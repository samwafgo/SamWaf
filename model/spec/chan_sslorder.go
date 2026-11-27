package spec

import "SamWaf/model"

type ChanSslOrder struct {
	Type          int
	Content       model.SslOrder
	Submitted     bool
	SourceOrderID string
}
