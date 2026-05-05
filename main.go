/*
Copyright 2021 Richard Kosegi

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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/rkosegi/cert-manager-webhook-active24/internal"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	defaultApiUrl       = "https://rest.active24.cz"
	defaultApiUserKey   = "apiUser"
	defaultApiSecretKey = "apiSecret"
)

type active24DNSProviderSolver struct {
	webhook.Solver
	k8sClient *kubernetes.Clientset
	ctx       context.Context
}

// active24DNSProviderConfig is the per-issuer configuration block.
type active24DNSProviderConfig struct {
	ApiSecretRef corev1.SecretReference `json:"apiSecretRef"`
	ApiUserKey   string                 `json:"apiUserKey,omitempty"`
	ApiSecretKey string                 `json:"apiSecretKey,omitempty"`
	Domain       string                 `json:"domain"`
	ServiceID    string                 `json:"serviceId,omitempty"`
	ApiUrl       string                 `json:"apiUrl,omitempty"`
}

func main() {
	klog.InitFlags(nil)
	if groupName := os.Getenv("GROUP_NAME"); groupName != "" {
		cmd.RunWebhookServer(groupName, &active24DNSProviderSolver{
			ctx: context.Background(),
		})
	} else {
		panic("GROUP_NAME environment variable must be specified")
	}
}

func (c *active24DNSProviderSolver) Name() string {
	return "active24"
}

func (c *active24DNSProviderSolver) Initialize(restConfig *rest.Config, _ <-chan struct{}) error {
	klog.V(2).Infof("Initialize")

	var err error
	if c.k8sClient, err = kubernetes.NewForConfig(restConfig); err != nil {
		return err
	}
	return nil
}

func (c *active24DNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(2).Infof("Present: fqdn=%s, zone=%s, key=%s", ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)

	name, err := c.recordName(ch)
	if err != nil {
		return err
	}

	config, err := clientConfig(c, ch)
	if err != nil {
		return err
	}

	client := internal.NewApiClient(config)
	record, err := client.FindTxtRecord(name, ch.Key)
	if err != nil {
		return err
	}

	klog.V(6).Infof("Record : %v", record)
	if record == nil {
		return client.NewTxtRecord(name, ch.Key, 300)
	}
	return client.UpdateTxtRecord(record.Id, name, ch.Key, 300)
}

func (c *active24DNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(2).Infof("CleanUp: zone=%s, fqdn=%s", ch.ResolvedZone, ch.ResolvedFQDN)

	config, err := clientConfig(c, ch)
	if err != nil {
		return err
	}

	name, err := c.recordName(ch)
	if err != nil {
		return err
	}

	client := internal.NewApiClient(config)

	record, err := client.FindTxtRecord(name, ch.Key)
	if err != nil {
		return err
	}

	klog.V(6).Infof("Existing record : %v", record)
	if record != nil {
		return client.DeleteTxtRecord(record.Id)
	}
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (active24DNSProviderConfig, error) {
	klog.V(6).Infof("loadConfig")
	cfg := active24DNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("unable to unmarshal provider config: %v", err)
	}
	return cfg, nil
}

func clientConfig(c *active24DNSProviderSolver, ch *v1alpha1.ChallengeRequest) (internal.Config, error) {
	var config internal.Config

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return config, err
	}
	config.DomainName = strings.TrimRight(cfg.Domain, ".")
	if config.DomainName == "" {
		return config, fmt.Errorf("domain is required")
	}
	config.ServiceID = cfg.ServiceID
	config.ApiUrl = defaultApiUrl
	if cfg.ApiUrl != "" {
		config.ApiUrl = cfg.ApiUrl
	}

	secretName := cfg.ApiSecretRef.Name
	if secretName == "" {
		return config, fmt.Errorf("apiSecretRef.name is required")
	}
	secretNamespace := cfg.ApiSecretRef.Namespace
	if secretNamespace == "" {
		secretNamespace = ch.ResourceNamespace
	}

	userKey := defaultApiUserKey
	if cfg.ApiUserKey != "" {
		userKey = cfg.ApiUserKey
	}
	secretKey := defaultApiSecretKey
	if cfg.ApiSecretKey != "" {
		secretKey = cfg.ApiSecretKey
	}

	klog.V(6).Infof("Reading secret '%s' (keys '%s', '%s') in namespace '%s'",
		secretName, userKey, secretKey, secretNamespace)
	sec, err := c.k8sClient.CoreV1().Secrets(secretNamespace).Get(c.ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return config, fmt.Errorf("unable to get secret `%s/%s`; %v", secretNamespace, secretName, err)
	}

	user, ok := sec.Data[userKey]
	if !ok {
		return config, fmt.Errorf("key %q not found in secret %s/%s", userKey, secretNamespace, secretName)
	}
	pass, ok := sec.Data[secretKey]
	if !ok {
		return config, fmt.Errorf("key %q not found in secret %s/%s", secretKey, secretNamespace, secretName)
	}

	config.ApiUser = string(user)
	config.ApiSecret = string(pass)
	return config, nil
}

func (c *active24DNSProviderSolver) recordName(ch *v1alpha1.ChallengeRequest) (string, error) {
	klog.V(4).Infof("recordName: ResolvedZone=%s, ResolvedFQDN=%s", ch.ResolvedZone, ch.ResolvedFQDN)
	domain := strings.TrimRight(ch.ResolvedZone, ".")
	regexStr := "(.+)\\." + domain + "\\."
	r := regexp.MustCompile(regexStr)
	name := r.FindStringSubmatch(ch.ResolvedFQDN)
	if len(name) != 2 {
		return "", fmt.Errorf("unable to extract name from FQDN '%s' using regex '%s'", ch.ResolvedFQDN, regexStr)
	}
	return strings.TrimRight(name[1], "."), nil
}
