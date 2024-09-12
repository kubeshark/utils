package sentry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/getsentry/sentry-go"
	"github.com/hashicorp/go-retryablehttp"
)

type Request struct {
	Service string `json:"service"`
	Version string `json:"version"`
}

type DSNResponse struct {
	DSN string `json:"dsn"`
}

func IsSentryEnabled() bool {
	return os.Getenv("SENTRY_ENABLED") == "true"
}

func Environment() string {
	sentryEnv := "undefined"
	if env, ok := os.LookupEnv("SENTRY_ENVIRONMENT"); ok {
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

func AddTags(tags map[string]string) {
	for k, v := range tags {
		if v != "" {
			sentry.ConfigureScope(func(scope *sentry.Scope) {
				scope.SetTag(k, v)
			})
		}
	}
}

func getDSNEndpoint() string {
	apiUrl, ok := os.LookupEnv("KUBESHARK_CLOUD_API_URL")
	if !ok {
		apiUrl = "https://api.kubeshark.co"
	}

	return fmt.Sprintf("%s/sentry", apiUrl)
}
