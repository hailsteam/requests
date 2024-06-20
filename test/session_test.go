package main

import (
	"testing"

	"github.com/hailsteam/requests"
)

func TestSession(t *testing.T) {
	session, _ := requests.NewClient(nil)
	for i := 0; i < 2; i++ {
		resp, err := session.Get(nil, "https://httpbin.org/anything")
		if err != nil {
			t.Error(err)
		}
		if i == 0 {
			if !resp.IsNewConn() { //return is NewConn
				t.Error("new conn error: ", i)
			}
		} else {
			if resp.IsNewConn() {
				t.Error("new conn error: ", i)
			}
		}
	}
}
