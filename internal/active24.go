/*
Copyright 2022 Richard Kosegi
Copyright 2026 iMithrellas

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package internal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// Config carries connection details for the Active24 REST API.
//
// ApiSecret is used to sign requests and is never sent directly.
// ServiceID is optional; when empty, DomainName is resolved via the service
// listing endpoint before DNS record calls.
type Config struct {
	ApiUser    string
	ApiSecret  string
	ApiUrl     string
	DomainName string
	ServiceID  string
}

// DnsRecord is the subset of the Active24 DNS record schema used by ACME DNS-01.
type DnsRecord struct {
	Id      int    `json:"id"`
	Type    string `json:"type,omitempty"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Ttl     int    `json:"ttl"`
}

type dnsRecordPage struct {
	CurrentPage  int         `json:"currentPage"`
	RowsPerPage  int         `json:"rowsPerPage"`
	TotalPages   int         `json:"totalPages"`
	TotalRecords int         `json:"totalRecords"`
	Data         []DnsRecord `json:"data"`
}

type createRecordRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Ttl     int    `json:"ttl"`
}

type updateRecordRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Ttl     int    `json:"ttl"`
}

type servicesResponse struct {
	Items []Service `json:"items"`
}

// Service is the subset of the legacy service schema used to resolve domains.
type Service struct {
	ID          int    `json:"id"`
	ServiceName string `json:"serviceName"`
	Name        string `json:"name"`
}

type ApiClient struct {
	baseURL string
	user    string
	secret  string
	domain  string
	service string
	http    *http.Client
}

func NewApiClient(config Config) *ApiClient {
	base := strings.TrimRight(config.ApiUrl, "/")
	return &ApiClient{
		baseURL: base,
		user:    config.ApiUser,
		secret:  config.ApiSecret,
		domain:  config.DomainName,
		service: config.ServiceID,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (a *ApiClient) serviceID() (string, error) {
	if a.service != "" {
		return a.service, nil
	}
	if a.domain == "" {
		return "", fmt.Errorf("domain is required")
	}

	services, err := a.GetServices()
	if err != nil {
		return "", err
	}
	for _, service := range services {
		if service.ServiceName == "domain" && service.Name == a.domain {
			a.service = strconv.Itoa(service.ID)
			return a.service, nil
		}
	}
	return "", fmt.Errorf("active24 domain service not found for %q", a.domain)
}

func (a *ApiClient) recordsPath() (string, error) {
	service, err := a.serviceID()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/v2/service/%s/dns/record", a.baseURL, url.PathEscape(service)), nil
}

func (a *ApiClient) recordPath(id int) (string, error) {
	service, err := a.serviceID()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/v2/service/%s/dns/record/%d", a.baseURL, url.PathEscape(service), id), nil
}

// do performs an HTTP request with Active24's HMAC-SHA1 signed Basic auth.
func (a *ApiClient) do(method, fullURL string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, fullURL, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	parsed, err := url.Parse(fullURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	ts := time.Now().UTC().Unix()
	canonical := fmt.Sprintf("%s %s %d", method, parsed.Path, ts)
	mac := hmac.New(sha1.New, []byte(a.secret))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	req.SetBasicAuth(a.user, signature)
	req.Header.Set("Date", time.Unix(ts, 0).UTC().Format(time.RFC3339))
	req.Header.Set("X-Date", time.Unix(ts, 0).UTC().Format("20060102T150405Z"))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	klog.V(8).Infof("HTTP %s %s", method, fullURL)
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("active24 API error: %s %s -> %d: %s",
			method, fullURL, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (a *ApiClient) GetServices() ([]Service, error) {
	var out servicesResponse
	if err := a.do(http.MethodGet, a.baseURL+"/v1/user/self/service", nil, &out); err != nil {
		return nil, fmt.Errorf("get active24 services: %w", err)
	}
	return out.Items, nil
}

// listTxtRecords filters by type only because Active24's name/content filters
// are not reliable for newly-created records.
func (a *ApiClient) listTxtRecords() ([]DnsRecord, error) {
	const pageSize = 100
	var all []DnsRecord
	page := 1
	for {
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("rowsPerPage", strconv.Itoa(pageSize))
		q.Set("filters[type][]", "TXT")

		var pageResp dnsRecordPage
		recordsPath, err := a.recordsPath()
		if err != nil {
			return nil, err
		}
		if err := a.do(http.MethodGet, recordsPath+"?"+q.Encode(), nil, &pageResp); err != nil {
			return nil, err
		}
		all = append(all, pageResp.Data...)

		if pageResp.TotalPages <= page || len(pageResp.Data) == 0 {
			break
		}
		page++
	}
	return all, nil
}

func (a *ApiClient) FindTxtRecord(name string, text string) (*DnsRecord, error) {
	klog.V(4).Infof("FindTxtRecord: service=%s, name=%s, text=%s", a.service, name, text)

	records, err := a.listTxtRecords()
	if err != nil {
		return nil, err
	}
	wantQuoted := `"` + text + `"`
	for i := range records {
		r := records[i]
		if !sameRecordName(r.Name, name) {
			continue
		}
		if r.Content == text || r.Content == wantQuoted || strings.Trim(r.Content, `"`) == text {
			return &r, nil
		}
	}
	return nil, nil
}

func sameRecordName(got, want string) bool {
	got = strings.TrimRight(got, ".")
	want = strings.TrimRight(want, ".")
	return got == want || strings.HasPrefix(got, want+".")
}

func (a *ApiClient) NewTxtRecord(name string, text string, ttl int) error {
	klog.V(4).Infof("NewTxtRecord: service=%s, name=%s, text=%s, ttl=%d", a.service, name, text, ttl)
	body := createRecordRequest{
		Type:    "TXT",
		Name:    name,
		Content: text,
		Ttl:     ttl,
	}
	recordsPath, err := a.recordsPath()
	if err != nil {
		return err
	}
	return a.do(http.MethodPost, recordsPath, body, nil)
}

func (a *ApiClient) UpdateTxtRecord(id int, name string, text string, ttl int) error {
	klog.V(4).Infof("UpdateTxtRecord: service=%s, id=%d, name=%s, text=%s, ttl=%d",
		a.service, id, name, text, ttl)
	body := updateRecordRequest{
		Name:    name,
		Content: text,
		Ttl:     ttl,
	}
	recordPath, err := a.recordPath(id)
	if err != nil {
		return err
	}
	return a.do(http.MethodPut, recordPath, body, nil)
}

func (a *ApiClient) DeleteTxtRecord(id int) error {
	klog.V(4).Infof("DeleteTxtRecord: service=%s, id=%d", a.service, id)
	recordPath, err := a.recordPath(id)
	if err != nil {
		return err
	}
	return a.do(http.MethodDelete, recordPath, nil, nil)
}
