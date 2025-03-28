package waftask

import (
	"SamWaf/global"
)

func TaskCC() {
	global.GWAF_CHAN_CLEAR_CC_WINDOWS <- 1
}
