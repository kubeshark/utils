package sentry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/getsentry/sentry-go"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"
)

const (
	SENTRY_ENABLED     = "SENTRY_ENABLED"
	SENTRY_ENVIRONMENT = "SENTRY_ENVIRONMENT"
	SENTRY_ACTIVE      = "SENTRY_ACTIVE"
	SENTRY_EMAIL       = "SENTRY_EMAIL"
	SENTRY_CLUSTER_ID  = "SENTRY_CLUSTER_ID"
)

type Request struct {
	Service string `json:"service"`
	Version string `json:"version"`
}

type DSNResponse struct {
	DSN string `json:"dsn"`
}

type Writer struct {
	mu          sync.RWMutex
	active      bool
	writer      io.Writer
	targetLevel zerolog.Level
}

func NewWriter(w io.Writer, level zerolog.Level) *Writer {
	return &Writer{
		writer:      w,
		targetLevel: level,
	}
}

func (pw *Writer) Write(p []byte) (int, error) {
	pw.mu.RLock()
	defer pw.mu.RUnlock()

	if !pw.active {
		return len(p), nil
	}

	var entry struct {
		Level zerolog.Level `json:"level"`
	}
	if err := json.Unmarshal(p, &entry); err != nil {
		return len(p), nil
	}

	if entry.Level <= pw.targetLevel {
		return pw.writer.Write(p)
	}
	return len(p), nil
}

func (pw *Writer) Activate() {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.active = true
}

func IsSentryEnabled() bool {
	return os.Getenv(SENTRY_ENABLED) == "true"
}

func Environment() string {
	sentryEnv := "undefined"
	if env, ok := os.LookupEnv(SENTRY_ENVIRONMENT); ok {
		sentryEnv = env
	}

	return sentryEnv
}

func GetDSN(ctx context.Context, service, version string) (string, error) {

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3 // Max retry attempts

	client := retryClient.StandardClient()

	endpoint := getDSNEndpoint()

	reqBody := Request{
		Service: service,
		Version: version,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("error marshalling request body: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("error creating POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil // Return empty string if not 200
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	var dsnResp DSNResponse
	err = json.Unmarshal(body, &dsnResp)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %v", err)
	}

	return dsnResp.DSN, nil
}

func (w *Writer) IsActive() bool {
	return w.active
}

func (w *Writer) Deactivate() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.active = false
}

func AddTags(tags map[string]string) {
	sentry.CurrentHub().ConfigureScope(func(scope *sentry.Scope) {
		for k, v := range tags {
			if v != "" {
				scope.SetTag(k, v)
			}
		}
	})
}

const (
	DEFAULT_CLOUD_API_URL = "https://api.kubehq.com"
)

func getDSNEndpoint() string {
	apiUrl := DEFAULT_CLOUD_API_URL
	return fmt.Sprintf("%s/sentry", apiUrl)
}
