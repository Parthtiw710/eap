package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// StartLocalTunnel starts the local tunnel client to poll the remote EAP gateway
// and forward requests to the local port on localhost.
func StartLocalTunnel(serverURL, token string, port int) {
	if serverURL == "" || token == "" {
		log.Fatal("Both serverURL and token are required to start the tunnel.")
	}

	localAddr := fmt.Sprintf("http://localhost:%d", port)
	log.Printf("Starting tunnel client pointing to %s", localAddr)
	log.Printf("Connecting to EAP gateway: %s", serverURL)

	client := &http.Client{
		Timeout: 45 * time.Second,
	}

	pollURL := fmt.Sprintf("%s/tunnel/poll?token=%s", serverURL, url.QueryEscape(token))

	for {
		resp, err := client.Get(pollURL)
		if err != nil {
			log.Printf("Connection error: %v, retrying in 3 seconds...", err)
			time.Sleep(3 * time.Second)
			continue
		}

		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			continue // Keep polling
		}

		if resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			log.Fatal("Invalid tunnel token or server authentication failed.")
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("Server error: Status %d - %s, retrying in 3 seconds...", resp.StatusCode, string(bodyBytes))
			time.Sleep(3 * time.Second)
			continue
		}

		var req PendingRequest
		err = json.NewDecoder(resp.Body).Decode(&req)
		resp.Body.Close()
		if err != nil {
			log.Printf("Failed to decode pending request: %v", err)
			continue
		}

		// Process the request in a goroutine
		go func(r PendingRequest) {
			localResp, err := forwardToLocal(r, localAddr)
			if err != nil {
				log.Printf("[%s] Local forward error: %v", r.ID, err)
				localResp = &TunnelResponse{
					Status:  http.StatusBadGateway,
					Headers: make(map[string][]string),
					Body:    []byte(fmt.Sprintf("Local forward error: %v", err)),
				}
			}

			err = sendResponseBack(serverURL, token, r.ID, localResp, client)
			if err != nil {
				log.Printf("[%s] Failed to send response back: %v", r.ID, err)
			}
		}(req)
	}
}

func forwardToLocal(req PendingRequest, localAddr string) (*TunnelResponse, error) {
	localURL := fmt.Sprintf("%s%s", localAddr, req.Path)
	if req.Query != "" {
		localURL = fmt.Sprintf("%s?%s", localURL, req.Query)
	}

	var bodyReader io.Reader
	if req.Body != nil {
		bodyReader = bytes.NewReader(req.Body)
	}

	localReq, err := http.NewRequest(req.Method, localURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, values := range req.Headers {
		for _, v := range values {
			localReq.Header.Add(k, v)
		}
	}

	localClient := &http.Client{
		Timeout: 20 * time.Second,
	}

	resp, err := localClient.Do(localReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string][]string)
	for k, v := range resp.Header {
		headers[k] = v
	}

	return &TunnelResponse{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    bodyBytes,
	}, nil
}

func sendResponseBack(serverURL, token, id string, tResp *TunnelResponse, client *http.Client) error {
	respondURL := fmt.Sprintf("%s/tunnel/respond?token=%s&id=%s", serverURL, url.QueryEscape(token), url.QueryEscape(id))
	
	bodyBytes, err := json.Marshal(tResp)
	if err != nil {
		return err
	}

	resp, err := client.Post(respondURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned non-200 status: %d - %s", resp.StatusCode, string(respBody))
	}

	return nil
}
