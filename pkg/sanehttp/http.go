package sanehttp

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

type Client struct {
	client http.Client
}

type Options struct {
	BearerToken *string
}

func NewClient(requestTimeout time.Duration, verifyCert bool) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if verifyCert == false {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		client: http.Client{
			Timeout:   requestTimeout,
			Transport: transport,
		},
	}
}

type Response struct {
	StatusCode int
	Response   []byte
}

func (c *Client) Post(url string, headers map[string]string, data io.Reader, contentType string, options *Options) (*Response, error) {
	request, err := http.NewRequest(http.MethodPost, url, data)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", contentType)
	if options.BearerToken != nil {
		request.Header.Set("Authorization", "Bearer "+*options.BearerToken)
	}

	if len(headers) > 0 {

		for k, v := range headers {
			request.Header.Set(k, v)
		}
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: response.StatusCode,
		Response:   body,
	}, nil
}
