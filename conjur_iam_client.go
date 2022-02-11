package conjurIamClient

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/codingconcepts/env"
)

type Payload struct {
	Host              string `json:"host"`
	XAmzDate          string `json:"x-amz-date"`
	XAmzSecurityToken string `json:"x-amz-security-token"`
	XAmzContentSHA256 string `json:"x-amz-content-sha256"`
	Authorization     string `json:"authorization"`
}

type ConjurDetails struct {
	Url       string `env:"CONJUR_APPLIANCE_URL" required="true"` // Conjur Host e.g. https://conjur.yourdomain.com
	Acct      string `env:"CONJUR_ACCOUNT" required="true"`       // Conjur Account e.g. default
	HostId    string `env:"CONJUR_AUTHN_LOGIN" required="true"`   // Host to Authenticate as e.g. host/policy/prefix/id
	ServiceId string `env:"AUTHN_IAM_SERVICE_ID" required="true"` // Authentication Service e.g. prod
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

type ConjurAuthResponse struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`

	// Error state
	Message string `json:"message,omitempty"`
}

func NewClientFromRole() (ConjurAuthResponse, error) {

	// Initialize response
	var conjurClient ConjurAuthResponse

	// Validate Role is available
	// TODO CHECK ROLE

	// Returns initialized Provider using EC2 IMDS Client by default
	svc := ec2rolecreds.New(func(options *ec2rolecreds.Options) {
		config.WithRegion(region)
	})

	// Retrieve retrieves credentials from the EC2 service.
	creds, err := svc.Retrieve(context.Background())
	if err != nil {
		conjurClient.Message = "Error retrieving credentials from EC2 Role Cred Service"
		return conjurClient, err
	}

	// Generate STS Request
	req, err := http.NewRequest("GET", ServiceUrl.String(), nil)
	if err != nil {
		conjurClient.Message = "Error generating STS Request"
		return conjurClient, err
	}

	// Create Signer using aws-sdk-go-v2/aws/signer
	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, xAmzContentSHA256, serviceID, region, time.Now().UTC(), func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = false
		o.LogSigning = true
	})
	if err != nil {
		conjurClient.Message = "Error obtaining signature from Signer"
		return conjurClient, err
	}

	// Create JSON from signer response header
	signerPayload := Payload{
		Host:              ServiceUrl.Host,
		XAmzDate:          req.Header.Get("X-Amz-Date"),
		XAmzSecurityToken: req.Header.Get("X-Amz-Security-Token"),
		Authorization:     req.Header.Get("Authorization"),
	}
	payload, err := json.Marshal(signerPayload)
	if err != nil {
		conjurClient.Message = "Error creating payload body from Signer Response"
		return conjurClient, err
	}

	// Declare / Read in Conjur Information
	conjur := ConjurDetails{}
	if err := env.Set(&conjur); err != nil {
		conjurClient.Message = "Error obtaining Conjur Details"
		return conjurClient, err
	}

	// Ensure Conjur Details are available and the fields aren't empty
	v := reflect.ValueOf(conjur)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Interface() == "" {
			conjurClient.Message = "Conjur Environment Variable not set"
			return conjurClient, nil
		}
	}

	// Build Conjur URL (Path Escape required on HOST ID to convert / to %2F)
	authUrl := conjur.Url + "/authn-iam/" + conjur.ServiceId + "/" + conjur.Acct + "/" + url.PathEscape(conjur.HostId) + "/authenticate"

	// Generate Conjur Client
	client := &http.Client{}
	conjurReq, err := http.NewRequest("POST", authUrl, bytes.NewBuffer(payload))
	if err != nil {
		conjurClient.Message = "Error generating the conjur client request"
		return conjurClient, err
	}
	conjurReq.Header.Add("Content-Type", "text/plain")
	conjurReq.Header.Add("Accept", "*/*")

	resp, err := client.Do(conjurReq)
	if err != nil {
		conjurClient.Message = "No response from Conjur Host"
		return conjurClient, err
	} else if resp.StatusCode == 401 || resp.StatusCode == 404 {
		conjurClient.Message = resp.Status
		return conjurClient, nil
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		conjurClient.Message = "Unable to read Conjur Response Body"
		return conjurClient, err
	}

	json.Unmarshal([]byte(respBytes), &conjurClient)

	return conjurClient, nil
}
