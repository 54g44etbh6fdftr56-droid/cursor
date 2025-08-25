package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9" // Updated import path
)

type Response struct {
	Body       string      `json:"body"`
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
}

var ctx = context.Background()
var rdb *redis.Client

func init() {
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
}

func hash(url string) string {
	h := sha256.New()
	h.Write([]byte(url))
	return hex.EncodeToString(h.Sum(nil))
}

func dynamic(req *http.Request) bool {
	if req.Method != http.MethodGet {
		return true
	}

	// Non-cacheable endpoints
	dynamicPaths := []string{
		"/panel",
	}
	for _, path := range dynamicPaths {
		if strings.HasPrefix(req.URL.Path, path) {
			return true
		}
	}

	return false
}

func forwardRequest(origReq *http.Request) (string, error) {
	// Create a new request to the origin server
	originURL := url.URL{
		Scheme:   "http",
		Host:     "localhost:8888",
		RawQuery: origReq.URL.RawQuery,
	}

	originURL = *originURL.JoinPath(origReq.URL.Path)

	// Create the new request with the same method, body, and headers
	req, err := http.NewRequest(origReq.Method, originURL.String(), origReq.Body)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Copy headers from the original request
	for key, values := range origReq.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Make the request to the origin server
	client := &http.Client{
		// Prevent automatic redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request to origin: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Create a Response struct to hold the response data
	response := Response{
		Body:       string(body),
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}

	jsonStr, err := json.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %v", err)
	}

	return string(jsonStr), nil
}

func cdnHandler(w http.ResponseWriter, req *http.Request) {
	var res string
	var err error
	if dynamic(req) {
		w.Header().Set("X-Cache", "dynamic")
		res, err = forwardRequest(req)
		if err != nil {
			http.Error(w, "Failed to fetch from origin: "+err.Error(), http.StatusBadGateway)
			return
		}
	} else {
		// Cacheable GET request
		key := hash(req.URL.String())
		res, err = rdb.Get(ctx, key).Result()
		if err == redis.Nil {
			// Cache miss, fetch from origin
			w.Header().Set("X-Cache", "miss")
			res, err = forwardRequest(req)
			if err != nil {
				http.Error(w, "Failed to fetch from origin: "+err.Error(), http.StatusBadGateway)
				return
			}
		} else if err != nil {
			// Redis error
			http.Error(w, "Redis error: "+err.Error(), http.StatusInternalServerError)
			return
		} else {
			// Cache hit
			w.Header().Set("X-Cache", "hit")
		}

		// Store the response in Redis with a 60-second expiration
		err = rdb.SetNX(ctx, key, res, 60*time.Second).Err()
		if err != nil {
			log.Printf("Failed to store in Redis: %v", err)
		}
	}
	var response Response
	err = json.Unmarshal([]byte(res), &response)
	if err != nil {
		http.Error(w, "Failed to unmarshal response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for key, value := range response.Headers {
		if key == "Content-Length" || key == "Etag" || key == "Last-Modified" {
			// Skip these headers
			continue
		}
		w.Header().Set(key, value[0])
	}
	w.WriteHeader(response.StatusCode)
	fmt.Fprintln(w, response.Body)
}

func main() {
	http.HandleFunc("/", cdnHandler)
	log.Println("Starting CDN service on :1337")
	log.Fatal(http.ListenAndServe(":1337", nil))
}
