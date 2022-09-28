package utils

import (
	"SamWaf/innerbean"
	"bytes"
	"context"
	"encoding/json"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"log"
)

// es帮助类
type EsHelper struct {
	es *elasticsearch.Client
}

func (eshelper *EsHelper) Init() {
	cfg := elasticsearch.Config{
		Addresses: []string{
			"http://82.156.235.106:9200",
		},
		// ...
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	eshelper.es = es
	log.Println(elasticsearch.Version)
	log.Println(es.Info())
}
func (eshelper *EsHelper) BatchInsert(weblogs innerbean.WebLog) {

	// Build the request body.
	data, err := json.Marshal(weblogs)
	if err != nil {
		log.Fatalf("Error marshaling document: %s", err)
	}
	req := esapi.IndexRequest{
		Index: "test",
		//DocumentID: strconv.Itoa(1 + 1),
		Body: bytes.NewReader(data),
		//Refresh:    "true",
	}

	// Perform the request with the client.
	res, err := req.Do(context.Background(), eshelper.es)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	log.Print(res)
}
