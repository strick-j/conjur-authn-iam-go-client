package conjurIamClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

type ConjurParams struct {
	IamAuthMethod   string // IAM IamAuthMethodod: "static", "iamrole", "assumerole", "profile"
	Profile         string // AWS Profile (e.g. Default)
	RoleArn         string // AWS Role ARN (required for assumeRole)
	RoleSessionName string // AWS Assume Role Session Name (required for assumeRole)
	AccessKey       string // AWS Access Key (Required for static)
	SecretKey       string // AWS Secret Key (Required for static)
	SessionToken    string // AWS Session Token (Optional for static)
	HostId          string // Host to Authenticate as e.g. host/policy/prefix/id
	ServiceId       string // Authentication Service e.g. prod
}

// STSAssumeRoleAPI defines the interface for the AssumeRole function.
type STSAssumeRoleAPI interface {
	AssumeRole(ctx context.Context,
		params *sts.AssumeRoleInput,
		optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// Set defaults as required by the aws-sdk-go-v2 package to obtain a Signed Token
var (
	xAmzContentSHA256 string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	serviceID         string = "sts"
	region            string = "us-east-1" // Region must be us-east-1 for the IAM Service Call
)

// NewClientIamClient requires a struct containing ConjurParameters.
// Parameters specify the Credential Generation IamAuthMethodod as well as specific Conjur
// Details.
// type ConjurParams struct {
// 		IamAuthMethod       string // IAM IamAuthMethodod: "static", "iamrole", "assumerole", "profile" (Required)
//		Profile      		string // AWS Profile (e.g. Default) (Required for Profile)
// 		RoleArn      		string // AWS Role ARN (Required for assumeRole)
//		Session      		string // AWS Assume Role Session Name (Required for assumeRole)
//		AccessKey    		string // AWS Access Key (Required for static)
//		SecretKey    		string // AWS Secret Key (Required for static)
//		SessionToken 		string // AWS Session Token (Optional for static)
//		HostId       		string // Host to Authenticate as e.g. host/policy/prefix/id (Required)
//		ServiceId    		string // Authentication Service e.g. prod (Required)
//	}
func NewConjurIamClient(params ConjurParams) (*conjurapi.Client, error) {
	if params.IamAuthMethod == "" || params.HostId == "" || params.ServiceId == "" {
		err := fmt.Errorf("required parameter not provided - IamAuthMethod, HostId, and ServiceId are required")
		panic(err)
	}

	// Obtain AWS based on context provided
	credentials, err := GetAwsCredentials(params)
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

	// Load Conjur Config - Checks .netrc, .conjurrc, and Environment Variables
	cfg, err := conjurapi.LoadConfig()
	if err != nil {
		panic(err)
	}

	// Get Conjur Authentication Token
	conjurSessionToken, err := GetConjurIAMSessionToken(*sigV4Payload, cfg, params)
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

func GetAwsCredentials(params ConjurParams) (*aws.Credentials, error) {
	switch strings.ToLower(params.IamAuthMethod) {
	case "static":
		// UPDATE TODO
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(params.AccessKey, params.SecretKey, params.SessionToken)),
			config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		credentials, err := GetIAMAssumedRoleMetadata(params, cfg)
		if err != nil {
			fmt.Printf("Error: %s", err)
			panic(err)
		}
		return credentials, nil
	case "assumerole":
		// Initial credentials loaded from SDK's default credential chain. Such as
		// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
		// Role. These credentials will be used to to make the STS Assume Role API.
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		// Obtain Credentials based on loaded config
		credentials, err := GetIAMAssumedRoleMetadata(params, cfg)
		if err != nil {
			fmt.Printf("Error: %s", err)
			panic(err)
		}
		return credentials, nil
	case "iamrole":
		// Obtain Credentials based on IAM Role Information
		credentials, err := GetIAMEC2RoleMetadata(params)
		if err != nil {
			fmt.Printf("Error: %s", err)
			panic(err)
		}
		return credentials, nil
	case "profile":
		// Comment here
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithSharedConfigProfile(params.Profile),
			config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		// Obtain Credentials based on provided profile. Assume Role.
		credentials, err := GetIAMAssumedRoleMetadata(params, cfg)
		if err != nil {
			fmt.Printf("Error: %s", err)
			panic(err)
		}
		return credentials, nil
	default:
		// No IamAuthMethodod provided, check if role or profile exist
		err := fmt.Errorf("error: no IamAuthMethodod parameter provided")
		return nil, err
	}
}

// GetIAMEC2RoleMetadata obtains AWS credentials from an EC2 Host IAM
// Role. If no role is assigned an error is returned.
func GetIAMEC2RoleMetadata(params ConjurParams) (*aws.Credentials, error) {
	// TODO: Check Profile - If not Default attempt to load from non default profile

	// Returns initialized Provider using EC2 IMDS Client by default
	provider := ec2rolecreds.New(func(options *ec2rolecreds.Options) {
		config.WithRegion(region)
	})

	// Retrieve retrieves credentials from the EC2 service.
	credentials, err := provider.Retrieve(context.Background())
	if err != nil {
		err = fmt.Errorf("unable to derive credentials from EC2 Role. Error: %s", err)
		return nil, err
	}

	return &credentials, nil
}

// GetAssumedRoleMetadata obtiains AWS credentials based on initial AWS credentials
// that are used to assume a role
func GetIAMAssumedRoleMetadata(params ConjurParams, cfg aws.Config) (*aws.Credentials, error) {
	// Create the credentials from AssumeRoleProvider to assume the role
	// referenced by the "myRoleARN" ARN.
	provider := sts.NewFromConfig(cfg, func(options *sts.Options) {
		config.WithRegion(region)
	})
	creds := stscreds.NewAssumeRoleProvider(provider, params.RoleArn)

	// Retrieve retrieves a set of temporary credentials for the assumed role
	credentials, err := creds.Retrieve(context.Background())
	if err != nil {
		panic(err)
	}

	return &credentials, nil
}

// GetIAMStaticMetadata obtains AWS credentials based on user provided credentials.
// Requires (Access Key ID, Secret Key, and Sessions
// Note: Should be used for testing purposes only
func GetIAMStaticMetadata(params ConjurParams) (*aws.Credentials, error) {
	// Uses user provided credentials to create aws config
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(params.AccessKey, params.SecretKey, params.SessionToken)),
	)
	if err != nil {
		panic(err)
	}

	// Retrieve retrieves a set of temporary credentials for the assumed role
	credentials, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		panic(err)
	}

	return &credentials, nil
}

// GetIAMProfileMetadata obtains AWS credentials based on a specified profile
// Note: The profile must exist in ~/.aws/config or ~/.aws/credentials
func GetIAMProfileMetadata(params ConjurParams) (*aws.Credentials, error) {
	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role.
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile(params.Profile),
		config.WithRegion(region))
	if err != nil {
		panic(err)
	}

	// Create the credentials from AssumeRoleProvider to assume the role
	// referenced by the "myRoleARN" ARN.
	provider := sts.NewFromConfig(cfg, func(options *sts.Options) {
		config.WithRegion(region)
	})

	creds := stscreds.NewAssumeRoleProvider(provider, params.RoleArn)

	// Retrieve retrieves a set of temporary credentials for the assumed role
	credentials, err := creds.Retrieve(context.Background())
	if err != nil {
		panic(err)
	}

	return &credentials, nil
}

// NewTokenFromIAM takes AWS credentials (Access Key ID, Secret Key ID, and Session Token)
// and uses the aws-sdk-go-v2 package to complete the AWS Signature Version 4 signing process
// https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
// The output of this process is the Authentication Token which can be used to authenticate to
// Conjur via the authn-iam authenticator.
func NewTokenFromIAM(credentials aws.Credentials) (*Sigv4Payload, error) {
	// ServiceUrl is used to query STS
	var ServiceUrl = &url.URL{
		Scheme:   "https",
		Host:     "sts.amazonaws.com",
		Path:     "/",
		RawQuery: "Action=GetCallerIdentity&Version=2011-06-15",
	}

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
func GetConjurIAMSessionToken(conjurAuthPayload Sigv4Payload, cfg conjurapi.Config, params ConjurParams) (authn.AuthnToken, error) {
	payload, err := json.Marshal(conjurAuthPayload)
	if err != nil {
		err = fmt.Errorf("error creating json payload body from AWS sigv4 signer response. Error: %s", err)
		return nil, err
	}

	// Build Conjur URL (Path Escape required on HOST ID to convert / to %2F)
	authUrl := cfg.ApplianceURL + "/authn-iam/" + params.ServiceId + "/" + cfg.Account + "/" + url.PathEscape(params.HostId) + "/authenticate"

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
		err = fmt.Errorf("no response from Conjur Host")
		return nil, err
	} else if resp.StatusCode == 401 || resp.StatusCode == 404 {
		err = fmt.Errorf("error 404 or 401: %s", resp.Status)
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
