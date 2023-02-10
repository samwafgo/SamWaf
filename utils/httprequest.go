package utils

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type RemoteRequest struct {
	client *http.Client
}

func InitRequest() *RemoteRequest {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	return &RemoteRequest{&http.Client{Transport: tr, Timeout: 5 * time.Second}}
}
func (r *RemoteRequest) GetRaw(uri string) ([]byte, error) {
	resp, err := r.client.Get(uri)
	if err != nil {
		log.Printf("client request error: url-> %s, %v ", uri, err)
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
