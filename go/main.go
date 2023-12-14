//package main
//
//import (
//	"encoding/base64"
//	"fmt"
//	"net/http"
//)
//
//type Response struct {
//	Version        string `json:"version"`
//	Commit         string `json:"commit"`
//	KafkaClsuterId string `json:"kafka_cluster_id"`
//}
//
////func main() {
////resp, err := http.Get("http://localhost:8083/")
////if err != nil {
////	fmt.Println("Error:", err)
////	return
////}
////defer resp.Body.Close()
////
////body, err := io.ReadAll(resp.Body)
////if err != nil {
////	fmt.Println("Error:", err)
////	return
////}
////
////fmt.Println(string(body))
////	fmt.Println(basicAuth())
////}
////func basicAuth() string {
////	var username string = "connect"
////	var passwd string = "connect"
////	client := &http.Client{}
////	req, err := http.NewRequest("GET", "http://localhost:8083", nil)
////	req.SetBasicAuth(username, passwd)
////	resp, err := client.Do(req)
////	if err != nil {
////		log.Fatal(err)
////	}
////	bodyText, err := io.ReadAll(resp.Body)
////	fmt.Println(resp.StatusCode)
////	s := string(bodyText)
////	return s
////}
//
//func basicAuth(username, password string) string {
//	auth := username + ":" + password
//	return base64.StdEncoding.EncodeToString([]byte(auth))
//}
//
//func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
//	req.Header.Add("Authorization", "Basic "+basicAuth("username1", "password123"))
//	return nil
//}
//
//func main() {
//	client := &http.Client{}
//
//	req, err := http.NewRequest("GET", "http://localhost/8083", nil)
//	fmt.Println(err)
//	req.Header.Add("Authorization", "Basic "+basicAuth("connect", "connect"))
//	resp, err := client.Do(req)
//	fmt.Println(err, resp)
//}

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	client := http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8083", http.NoBody)
	if err != nil {
		log.Fatal(err)
	}

	req.SetBasicAuth("thisismyusername", "thisismypass")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Status: %d\n", res.StatusCode)
	fmt.Printf("Body: %s\n", string(resBody))
}
