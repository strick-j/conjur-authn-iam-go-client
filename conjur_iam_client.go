package conjurIamClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

type Sigv4Payload struct {
	Host              string `json:"host"`
	XAmzDate          string `json:"x-amz-date"`
	XAmzSecurityToken string `json:"x-amz-security-token"`
	XAmzContentSHA256 string `json:"x-amz-content-sha256"`
	Authorization     string `json:"authorization"`
}

type ConjurDetails struct {
	HostId    string // Host to Authenticate as e.g. host/policy/prefix/id
	ServiceId string // Authentication Service e.g. prod
}

// Set defaults as required by the aws-sdk-go-v2 package to obtain a Signed Token
var (
	xAmzContentSHA256 string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	serviceID         string = "sts"
	region            string = "us-east-1" // Region must be us-east-1 for the IAM Service Call
)

var ServiceUrl = &url.URL{
	Scheme:   "https",
	Host:     "sts.amazonaws.com",
	Path:     "/",
	RawQuery: "Action=GetCallerIdentity&Version=2011-06-15",
}

// NewClientFromRole returns a Conjur Client () based on AWS Role provided
// Requires ConjurDetails - HostId (e.g. host/policy/prefix/id) and ServiceId (e.g. Prod)
func NewClientFromRole(details ConjurDetails) (*conjurapi.Client, error) {
	// Load Conjur Config - Checks .netrc, .conjurrc, and Environment Variables
	cfg, err := conjurapi.LoadConfig()
	if err != nil {
		panic(err)
	}

	// Obtain Credentials based on IAM Role Information
	credentials, err := GetIAMRoleMetadata()
	if err != nil {
		fmt.Printf("Error: %s", err)
		panic(err)
	}

	// Get AWS Signature Version 4 signing token based on IAM Role
	sigV4Payload, err := NewTokenFromIAM(*credentials)
	if err != nil {
		fmt.Printf("Error: %s", err)
		panic(err)
	}

	// Get Conjur Authentication Token
	conjurSessionToken, err := GetConjurIAMSessionToken(*sigV4Payload, cfg, details)
	if err != nil {
		fmt.Printf("Error: %s", err)
		panic(err)
	}

	// Create Conjur Client from Authentication Token and Config
	conjurClient, err := conjurapi.NewClientFromToken(cfg, string(conjurSessionToken.Raw()))
	if err != nil {
		fmt.Printf("Error: %s", err)
		panic(err)
	}

	return conjurClient, nil
}

// GetIAMRoleMetadata obtiains AWS credentials from an EC2 Host IAM
// Role. If no role is assigned an error is returned.
func GetIAMRoleMetadata() (*aws.Credentials, error) {
	// Returns initialized Provider using EC2 IMDS Client by default
	provider := ec2rolecreds.New(func(options *ec2rolecreds.Options) {
		config.WithRegion(region)
	})

	// Retrieve retrieves credentials from the EC2 service.
	credentials, err := provider.Retrieve(context.Background())
	if err != nil {
		err = fmt.Errorf("enable to derive credentials from EC2 Role. Error: %s", err)
		return nil, err
	}

	return &credentials, err
}

// NewTokenFromIAM takes AWS credentials (Access Key ID, Secret Key ID, and Session Token)
// and uses the aws-sdk-go-v2 package to complete the AWS Signature Version 4 signing process
// https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
// The output of this process is the Authentication Token which can be used to authenticate to
// Conjur via the authn-iam authenticator.
func NewTokenFromIAM(credentials aws.Credentials) (*Sigv4Payload, error) {
	// Generate STS Request
	req, err := http.NewRequest("GET", ServiceUrl.String(), nil)
	if err != nil {
		err = fmt.Errorf("error Generating STS Request : %s", err)
		return nil, err
	}

	// Create Signer using aws-sdk-go-v2/aws/signer with blank payload
	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), credentials, req, xAmzContentSHA256, serviceID, region, time.Now().UTC(), func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = false
		o.LogSigning = true
	})
	if err != nil {
		err = fmt.Errorf("unable to create AWS sigv4 Signer : %s", err)
		return nil, err
	}

	// Create JSON from signer response header
	conjurAuthPayload := Sigv4Payload{
		Host:              ServiceUrl.Host,
		XAmzDate:          req.Header.Get("X-Amz-Date"),
		XAmzSecurityToken: req.Header.Get("X-Amz-Security-Token"),
		XAmzContentSHA256: xAmzContentSHA256,
		Authorization:     req.Header.Get("Authorization"),
	}

	return &conjurAuthPayload, nil
}

// Get ConjurIAMSessionToken utilizes the Sigv4Payload as the the body to authenticate
// via the authn-iam Conjur Authenticator
func GetConjurIAMSessionToken(conjurAuthPayload Sigv4Payload, cfg conjurapi.Config, details ConjurDetails) (authn.AuthnToken, error) {
	payload, err := json.Marshal(conjurAuthPayload)
	if err != nil {
		err = fmt.Errorf("error creating json payload body from AWS sigv4 signer response. Error: %s", err)
		return nil, err
	}

	// Build Conjur URL (Path Escape required on HOST ID to convert / to %2F)
	authUrl := cfg.ApplianceURL + "/authn-iam/" + details.ServiceId + "/" + cfg.Account + "/" + url.PathEscape(details.HostId) + "/authenticate"

	// Generate Conjur Client
	client := &http.Client{}
	conjurReq, err := http.NewRequest("POST", authUrl, bytes.NewBuffer(payload))
	if err != nil {
		err = fmt.Errorf("error generating the conjur client request : %s", err)
		return nil, err
	}
	conjurReq.Header.Add("Content-Type", "text/plain")
	conjurReq.Header.Add("Accept", "*/*")

	resp, err := client.Do(conjurReq)
	if err != nil {
		fmt.Errorf("No response from Conjur Host")
		return nil, err
	} else if resp.StatusCode == 401 || resp.StatusCode == 404 {
		err = fmt.Errorf("Error 404 or 401: ", resp.Status)
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err := fmt.Errorf("unable to read Conjur Response Body : %s", err)
		return nil, err
	}

	// Generate Conjur Authentication Token from Conjur Byte Response
	conjurAuthToken, err := authn.NewToken(respBytes)
	if err != nil {
		err = fmt.Errorf("unable to generate Conjur Token from Conjur Byte Response. Error: %s", err)
		return nil, err
	}

	return conjurAuthToken, nil
}
