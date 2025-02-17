package middleware

import (
	"SamWaf/global"
	"SamWaf/wafsec"
	"bytes"
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
			decryptBytes, _ := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)

			//fmt.Println("Raw body解密:", string(deBytes))
			// Store the modified body back in the request
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(decryptBytes))
		} else if c.Request.Header.Get("accept") == ", text/event-stream" {
			decryptBytes, _ := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(decryptBytes))
		}
		c.Next()
	}
}
