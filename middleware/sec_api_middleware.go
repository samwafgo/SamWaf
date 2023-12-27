package middleware

import (
	"SamWaf/global"
	"SamWaf/wafsec"
	"bytes"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
)

// SecApi 鉴权中间件
func SecApi() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read the body and make a backup for later use
		bodyBytes, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset the request body to original

		//fmt.Println("Header ", c.Request.Header["Content-Type"])
		// Your preprocessing logic here
		// For example, reading raw body and doing some operations
		//fmt.Println("Raw body:", string(bodyBytes))

		if c.Request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			// Modify the bodyBytes if necessary
			// ...
			base64Bytes, _ := base64.StdEncoding.DecodeString(string(bodyBytes))
			deBytes := wafsec.AesDecrypt(base64Bytes, global.GWAF_COMMUNICATION_KEY)

			//fmt.Println("Raw body解密:", string(deBytes))
			// Store the modified body back in the request
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(deBytes))
		}
		c.Next()
	}
}
