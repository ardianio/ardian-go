package ardian

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type LicenseKey string
type PolicyID string
type UserID string

type IReadOnlyClient interface {
	// CheckIntegrity offline validation that a signed license is valid.
	CheckIntegrity(License) bool
	// IsExpired offline validation that a signed license is expired.
	IsExpired(License) bool
	// IsValid online validation of a license key.
	IsValid(LicenseKey) (ValidResp, error)

	// SetFingerprintFn sets the function to fingerprint a machine.
	SetFingerprintFn(func() string)

	// SetNowFn sets a function to get the current time.
	// This can be useful to get the current time from a web service.
	// IsExpired will use this function to compare the license expiry.
	SetNowFn(func() time.Time)
}

type IClient interface {
	IReadOnlyClient
	SuspendLicense(LicenseKey) (ApiResp, error)
	RestoreLicense(LicenseKey) (ApiResp, error)
	ActivateMachine(LicenseKey) (ApiResp, error)
	CreatePolicy(policyName string, duration *int64, maxMachines *int32) (ApiResp, error)
	CreateUser(username, firstName, lastName, email, password string) (ApiResp, error)
	CreateLicense(policyID PolicyID, userID UserID, licenseName *string, metadata map[string]interface{}) (ApiResp, error)
}

type License struct {
	signature string
	content   string
	ID        string
	PolicyID  string `yaml:"policy_id"`
	Name      *string
	Expiry    *time.Time
	Created   time.Time
	Metadata  map[string]interface{}
}

func ParseLicense(raw string) (License, error) {
	license := License{}
	separator := "\n-----BEGIN SIGNATURE-----"
	parts := strings.Split(raw, separator)
	if len(parts) != 2 {
		return license, errors.New("failed to parse license")
	}
	license.content = parts[0]
	license.signature = separator + parts[1]
	if err := yaml.Unmarshal([]byte(license.content), &license); err != nil {
		return license, errors.New("failed to parse yaml")
	}
	return license, nil
}

// CheckIntegrity verify that the license content and signature matches.
func (l License) CheckIntegrity(pubkey string) bool {
	block, rest := pem.Decode([]byte(pubkey))
	if len(rest) != 0 {
		return false
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	signatureBlock, rest := pem.Decode([]byte(l.signature))
	if len(rest) != 0 {
		return false
	}
	hash := sha256.New()
	hash.Write([]byte(l.content))
	hashed := hash.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed, signatureBlock.Bytes) == nil
}

// IsExpired locally verify that the license is not expired.
func (l License) IsExpired() bool {
	if l.Expiry == nil {
		return false
	}
	return time.Now().After(*l.Expiry)
}

// getMacAddr gets the MAC hardware address of the host machine
func getMacAddr() (addr string) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				// Don't use random as we have a real address
				addr = i.HardwareAddr.String()
				break
			}
		}
	}
	return
}

func DefaultFingerprint() string {
	mac := getMacAddr()
	hash := sha256.New()
	hash.Write([]byte(mac))
	hashed := hash.Sum(nil)
	return fmt.Sprintf("%x", hashed)
}

type ClientOptions struct {
	Scheme string
	Host   string
	Port   int
	PubKey string
	ApiKey string
}

type baseClient struct {
	scheme           string
	host             string
	port             int
	pubkey           string
	getFingerprintFn func() string
	nowFn            func() time.Time
}

type adminClient struct {
	readOnlyClient
	apiKey string
}

type ApiResp struct {
	Success bool
	Message string
}

func (c *baseClient) baseURL() string {
	return c.scheme + "://" + c.host + ":" + strconv.Itoa(c.port)
}

func (c *baseClient) post(endpoint string, data url.Values, out interface{}) error {
	resp, err := http.PostForm(c.baseURL()+endpoint, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	by, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(by, out); err != nil {
		return err
	}
	return nil
}

func (c *adminClient) SuspendLicense(licenseKey LicenseKey) (ApiResp, error) {
	data := url.Values{"key": []string{string(licenseKey)}}
	var res ApiResp
	if err := c.post("/api/v1/licenses/actions/suspend", data, &res); err != nil {
		return ApiResp{}, err
	}
	return res, nil
}

func (c *adminClient) RestoreLicense(licenseKey LicenseKey) (ApiResp, error) {
	data := url.Values{"key": []string{string(licenseKey)}}
	var res ApiResp
	if err := c.post("/api/v1/licenses/actions/restore", data, &res); err != nil {
		return ApiResp{}, err
	}
	return res, nil
}

func (c *adminClient) ActivateMachine(licenseKey LicenseKey) (ApiResp, error) {
	data := url.Values{"key": []string{string(licenseKey)}}
	var res ApiResp
	if err := c.post("/api/v1/machines", data, &res); err != nil {
		return ApiResp{}, err
	}
	return res, nil
}

func (c *adminClient) CreatePolicy(policyName string, duration *int64, maxMachines *int32) (ApiResp, error) {
	data := url.Values{"policy_name": []string{policyName}}
	var res ApiResp
	if err := c.post("/api/v1/policies", data, &res); err != nil {
		return ApiResp{}, err
	}
	return res, nil
}

func (c *adminClient) CreateUser(username, firstName, lastName, email, password string) (ApiResp, error) {
	data := url.Values{"username": []string{username}}
	var res ApiResp
	if err := c.post("/api/v1/users", data, &res); err != nil {
		return ApiResp{}, err
	}
	return res, nil
}

func (c *adminClient) CreateLicense(policyID PolicyID, userID UserID, licenseName *string, metadata map[string]interface{}) (ApiResp, error) {
	data := url.Values{"username": []string{string(policyID)}}
	var res ApiResp
	if err := c.post("/api/v1/licenses", data, &res); err != nil {
		return ApiResp{}, err
	}
	return res, nil
}

// readOnlyClient Read-Only client.
type readOnlyClient struct {
	baseClient
}

func NewAdminClient(opts *ClientOptions) (IClient, error) {
	client := new(adminClient)
	client.scheme = "http"
	client.host = "127.0.0.1"
	client.port = 8080
	client.getFingerprintFn = DefaultFingerprint
	client.nowFn = time.Now
	if opts != nil {
		if opts.Scheme == "http" || opts.Scheme == "https" {
			client.scheme = opts.Scheme
		}
		if opts.Host != "" {
			client.host = opts.Host
		}
		if opts.Port != 0 {
			client.port = opts.Port
		}
		client.pubkey = opts.PubKey
		client.apiKey = opts.ApiKey
	}
	return client, nil
}

func NewReadOnlyClient(opts *ClientOptions) (IReadOnlyClient, error) {
	client := new(readOnlyClient)
	client.scheme = "http"
	client.host = "127.0.0.1"
	client.port = 8080
	client.getFingerprintFn = DefaultFingerprint
	client.nowFn = time.Now
	if opts != nil {
		if opts.Scheme == "http" || opts.Scheme == "https" {
			client.scheme = opts.Scheme
		}
		if opts.Host != "" {
			client.host = opts.Host
		}
		if opts.Port != 0 {
			client.port = opts.Port
		}
		client.pubkey = opts.PubKey
	}
	return client, nil
}

func (c *readOnlyClient) SetFingerprintFn(fn func() string) {
	c.getFingerprintFn = fn
}

func (c *readOnlyClient) SetNowFn(fn func() time.Time) {
	c.nowFn = fn
}

func (c readOnlyClient) CheckIntegrity(l License) bool {
	return l.CheckIntegrity(c.pubkey)
}

func (c readOnlyClient) IsExpired(l License) bool {
	if l.Expiry == nil {
		return false
	}
	return c.nowFn().After(*l.Expiry)
}

type ValidResp struct {
	Valid   bool
	Message string
}

// IsValid verify with backend service if the key is valid.
func (c readOnlyClient) IsValid(key LicenseKey) (ValidResp, error) {
	// fingerprint := c.getFingerprintFn()
	// hostname, _ := os.Hostname()
	data := url.Values{"key": []string{string(key)}}
	var res ValidResp
	if err := c.post("/api/v1/licenses/actions/validate-key", data, &res); err != nil {
		return ValidResp{}, err
	}
	return res, nil
}
