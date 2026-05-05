/*
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

package internal_test

import (
	"os"
	"testing"
	"time"

	"github.com/rkosegi/cert-manager-webhook-active24/internal"
)

// liveClient returns a client configured from environment variables.
//
// Required env vars:
//
//	ACTIVE24_USER   - API key
//	ACTIVE24_SECRET - API secret
//	ACTIVE24_DOMAIN - domain name as registered in Active24 (e.g. example.com)
//
// Optional:
//
//	ACTIVE24_API_URL    - base URL (default: https://rest.active24.cz)
//	ACTIVE24_SERVICE_ID - numeric Active24 service ID; skips domain lookup when set
func liveClient(t *testing.T) *internal.ApiClient {
	t.Helper()
	user := os.Getenv("ACTIVE24_USER")
	secret := os.Getenv("ACTIVE24_SECRET")
	domain := os.Getenv("ACTIVE24_DOMAIN")
	serviceID := os.Getenv("ACTIVE24_SERVICE_ID")
	if user == "" || secret == "" || domain == "" {
		t.Skip("skipping live test: set ACTIVE24_USER, ACTIVE24_SECRET and ACTIVE24_DOMAIN to run")
	}
	apiURL := os.Getenv("ACTIVE24_API_URL")
	if apiURL == "" {
		apiURL = "https://rest.active24.cz"
	}
	return internal.NewApiClient(internal.Config{
		ApiUser:    user,
		ApiSecret:  secret,
		ApiUrl:     apiURL,
		DomainName: domain,
		ServiceID:  serviceID,
	})
}

// TestLiveFindNonExistentRecord verifies that looking up a record that does
// not exist returns (nil, nil) rather than an error.
func TestLiveFindNonExistentRecord(t *testing.T) {
	client := liveClient(t)

	rec, err := client.FindTxtRecord("_acme-challenge-webhook-test-nonexistent", "doesnotexist")
	if err != nil {
		t.Fatalf("FindTxtRecord returned error: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil record, got: %+v", rec)
	}
}

// TestLiveCreateFindDelete covers the client flow used by Present and CleanUp.
func TestLiveCreateFindDelete(t *testing.T) {
	const (
		name    = "_acme-challenge-webhook-test"
		content = "webhook-test-token-12345"
		ttl     = 60
	)

	client := liveClient(t)

	existing, err := client.FindTxtRecord(name, content)
	if err != nil {
		t.Fatalf("pre-clean FindTxtRecord: %v", err)
	}
	if existing != nil {
		t.Logf("found leftover record id=%d, deleting before test", existing.Id)
		if err := client.DeleteTxtRecord(existing.Id); err != nil {
			t.Fatalf("pre-clean DeleteTxtRecord: %v", err)
		}
	}

	t.Log("Creating TXT record...")
	if err := client.NewTxtRecord(name, content, ttl); err != nil {
		t.Fatalf("NewTxtRecord: %v", err)
	}

	t.Log("Finding TXT record...")
	var rec *internal.DnsRecord
	for i := 0; i < 10; i++ {
		rec, err = client.FindTxtRecord(name, content)
		if err != nil {
			t.Fatalf("FindTxtRecord: %v", err)
		}
		if rec != nil {
			break
		}
		t.Log("record not visible yet; retrying...")
		time.Sleep(2 * time.Second)
	}
	if rec == nil {
		t.Fatal("FindTxtRecord returned nil after creation")
	}
	t.Logf("Found record: id=%d name=%s content=%s ttl=%d", rec.Id, rec.Name, rec.Content, rec.Ttl)

	t.Log("Deleting TXT record...")
	if err := client.DeleteTxtRecord(rec.Id); err != nil {
		t.Fatalf("DeleteTxtRecord: %v", err)
	}

	t.Log("Confirming deletion...")
	gone, err := client.FindTxtRecord(name, content)
	if err != nil {
		t.Fatalf("post-delete FindTxtRecord: %v", err)
	}
	if gone != nil {
		t.Errorf("expected record to be deleted, but still found: %+v", gone)
	}
}
