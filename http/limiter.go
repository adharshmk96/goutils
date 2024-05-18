package http

import (
	"golang.org/x/time/rate"
	"net/http"
)

type RateLimitedClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

func NewRateLimitedClient(rps int) *RateLimitedClient {
	return &RateLimitedClient{
		client:  &http.Client{},
		limiter: rate.NewLimiter(rate.Limit(rps), 1),
	}
}

func (c *RateLimitedClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
