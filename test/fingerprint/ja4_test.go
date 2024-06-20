package main

import (
	"log"
	"net/textproto"
	"slices"
	"testing"

	"github.com/hailsteam/requests"
)

func TestOrderHeaders(t *testing.T) {

	headers := requests.NewOrderMap()
	headers.Set("Accept-Encoding", "gzip, deflate, br")
	headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	headers.Set("User-Agent", requests.UserAgent)
	headers.Set("Accept-Language", requests.AcceptLanguage)
	headers.Set("Sec-Ch-Ua", requests.SecChUa)
	headers.Set("Sec-Ch-Ua-Mobile", "?0")
	headers.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	resp, err := requests.Get(nil, "https://tools.scrapfly.io/api/fp/anything", requests.RequestOption{
		Headers: headers,
		// ForceHttp1: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := resp.Json()
	header_order := jsonData.Find("ordered_headers_key")
	if !header_order.Exists() {
		t.Fatal("not found akamai")
	}
	i := -1
	log.Print(header_order)
	// log.Print(headers.Keys())
	kks := []string{}
	for _, kk := range headers.Keys() {
		kks = append(kks, textproto.CanonicalMIMEHeaderKey(kk))
	}
	for _, key := range header_order.Array() {
		kk := textproto.CanonicalMIMEHeaderKey(key.String())
		if slices.Contains(kks, kk) {
			i2 := slices.Index(kks, textproto.CanonicalMIMEHeaderKey(kk))
			if i2 < i {
				log.Print(header_order)
				t.Fatal("not equal")
			}
			i = i2
		}
	}
}
