package conjurIamClient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
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

type ConjurIamParams struct {
	IamAuthMethod   string // IAM IamAuthMethodod: "static", "iamrole", "assumerole", "profile"
	Profile         string // AWS Profile (e.g. Default)
	RoleArn         string // AWS Role ARN (required for assumeRole)
	RoleSessionName string // AWS Assume Role Session Name (required for assumeRole)
	AccessKey       string // AWS Access Key (Required for static)
	SecretKey       string // AWS Secret Key (Required for static)
	SessionToken    string // AWS Session Token (Optional for static)
}

type authnVars struct {
	conjurLogin     string // Login for Conjur authn-iam URL Generation (e.g. host/policy/prefix/id)
	conjurServiceId string // Service ID for Conjur authn-iam URL Generation (e.g. default, prod, etc..)
}

type routerURL string

// Set defaults as required by the aws-sdk-go-v2 package to obtain a Signed Token
var (
	xAmzContentSHA256 string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	awsServiceID      string = "sts"
	region            string = "us-east-1" // Region must be us-east-1 for the IAM Service Call
)

// NewConjurIamClient requires a struct containing specific Conjur IAM Parameters
// Parameters specify the Credential Generation IamAuthMethodod as well as specific Conjur
// Details. Examples usage in ./examples/
// type ConjurParams struct {
// 		IamAuthMethod       string // IAM IamAuthMethodod: "static", "ec2role", "assumerole", "profile" (Required)
//		Profile      		string // AWS Profile (e.g. Default) (Required for Profile)
// 		RoleArn      		string // AWS Role ARN (Required for assumeRole)
//		Session      		string // AWS Assume Role Session Name (Required for assumeRole)
//		AccessKey    		string // AWS Access Key (Required for static)
//		SecretKey    		string // AWS Secret Key (Required for static)
//		SessionToken 		string // AWS Session Token (Optional for static)
//	}
func (p ConjurIamParams) NewConjurIamClient() (*conjurapi.Client, error) {
	// Validate IAM Authentication Method is present
	if p.IamAuthMethod == "" {
		panic(fmt.Errorf("required parameter not provided - IamAuthMethod, HostId, and ServiceId are required"))
	}

	// Load Conjur Config - Checks .netrc, .conjurrc, and Environment Variables
	cfg, err := conjurapi.LoadConfig()
	if err != nil {
		return nil, err
	}

	// Validate Conjur Service ID and Login are present
	authnVariables, err := authnVarsValidate(cfg)
	if err != nil {
		return nil, err
	}

	// Obtain AWS based on context provided
	credentials, err := getAwsCredentials(p)
	if err != nil {
		return nil, err
	}

	// Get AWS Signature Version 4 signing token based on IAM Role
	sigV4Payload, err := newTokenFromIAM(*credentials)
	if err != nil {
		return nil, err
	}

	// Get Conjur Authentication Token
	authnToken, err := getConjurIAMSessionToken(*sigV4Payload, cfg, *authnVariables)
	if err != nil {
		return nil, err
	}

	// Create Conjur Client from Authentication Token and Config
	conjurClient, err := conjurapi.NewClientFromToken(cfg, string(authnToken.Raw()))
	if err != nil {
		return nil, err
	}

	return conjurClient, nil
}
func authnVarsValidate(cfg conjurapi.Config) (*authnVars, error) {
	// Obtain Conjur authn-iam Service ID -
	authnIamServiceID := os.Getenv("CONJUR_AUTHN_IAM_SERVICE_ID")
	if authnIamServiceID == "" {
		return nil, fmt.Errorf("environment Variable for CONJUR_AUTHN_IAM_SERVICE_ID not found")
	}

	// Retrieve Conjur Login from Env or .Netrc
	var login string
	if loginPair, err := conjurapi.LoginPairFromEnv(); err == nil && loginPair.Login != "" {
		login = loginPair.Login
	} else if loginPair, err := conjurapi.LoginPairFromNetRC(cfg); err == nil && loginPair.Login != "" {
		login = loginPair.Login
	} else {
		return nil, fmt.Errorf("unable to detect Conjur Login Identity (e.g. host/policy/prefix/id)")
	}

	authnVars := authnVars{
		conjurLogin:     login,
		conjurServiceId: authnIamServiceID,
	}

	return &authnVars, nil
}

func getAwsCredentials(p ConjurIamParams) (*aws.Credentials, error) {
	iamAuthMethod := strings.ToLower(p.IamAuthMethod)

	if iamAuthMethod == "ec2role" {
		// Returns initialized Client using EC2 IMDS Client by default
		provider := ec2rolecreds.New(func(options *ec2rolecreds.Options) {
			config.WithRegion(region)
		})

		// Retrieve retrieves credentials from the EC2 service.
		credentials, err := provider.Retrieve(context.Background())
		if err != nil {
			return nil, err
		}

		return &credentials, nil

	} else if iamAuthMethod == "profile" || iamAuthMethod == "static" || iamAuthMethod == "assumerole" {
		// Validate that a Role ARN is provided
		if p.RoleArn == "" {
			return nil, fmt.Errorf("Role Arn not provided - Role Arn is required for assumption")
		}

		// Create AWS Configuration based on "method" and "parameters"
		// The methods - profile, static, and assumerole all rely on AWS Role Assumption via the
		// STS Service. Each method uses a specific set of credentials.
		// Methods:
		// -     static: uses provided static credentials to attempt role assumption (AKID, SECRET KEY ID, SESSION TOKEN)
		// -    profile: loads a specified profile (e.g. Default) and then attempts to assume the specified role.
		//               The profile should contain credentials for this use case.
		// - assumerole: attempts to use environment variables, default configs, or the host role to attempt specified role assumption
		cfg, err := p.getAwsConfig()
		if err != nil {
			return nil, err
		}

		// Create STS Client
		c := sts.NewFromConfig(*cfg, func(options *sts.Options) {
			config.WithRegion(region)
		})

		// Create STS Provider
		provider := stscreds.NewAssumeRoleProvider(c, p.RoleArn)

		// Retrieve temporary credentials for the assumed role
		credentials, err := provider.Retrieve(context.Background())
		if err != nil {
			panic(err)
		}

		return &credentials, nil

	} else {
		// No match for method identified, return error
		return nil, fmt.Errorf("incorrect method provided, method provided %s", p.IamAuthMethod)
	}
}

// getAwsConfig returns the appropriate AWS Configuration based on the method and parameters
// provided.
func (p *ConjurIamParams) getAwsConfig() (*aws.Config, error) {
	switch strings.ToLower(p.IamAuthMethod) {
	case "static":
		if p.AccessKey == "" || p.SecretKey == "" {
			return nil, fmt.Errorf("recieved static method for IAM Role Assumption but did not recieve AccessKey or SecretKey")
		}
		// Use provided static credentials to generate AWS Conig
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(p.AccessKey, p.SecretKey, p.SessionToken)),
			config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		return &cfg, nil
	case "assumerole":
		// Initial credentials loaded from SDK's default credential chain. Such as
		// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
		// Role. These credentials will be used to to make the STS Assume Role API.
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		return &cfg, nil
	case "profile":
		// Use provided profile to generate AWS Config
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithSharedConfigProfile(p.Profile),
			config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		return &cfg, nil
	}
	err := fmt.Errorf("invalid parameters")
	return nil, err
}

// newTokenFromIAM takes AWS credentials (Access Key ID, Secret Key ID, and Session Token)
// and uses the aws-sdk-go-v2 package to complete the AWS Signature Version 4 signing process
// https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
// The output of this process is the Authentication Token which can be used to authenticate to
// Conjur via the authn-iam authenticator.
func newTokenFromIAM(credentials aws.Credentials) (*Sigv4Payload, error) {
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
	err = signer.SignHTTP(context.Background(), credentials, req, xAmzContentSHA256, awsServiceID, region, time.Now().UTC(), func(o *v4.SignerOptions) {
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

// getConjurIAMSessionToken utilizes the Sigv4Payload as the the body to authenticate
// via the authn-iam Conjur Authenticator
func getConjurIAMSessionToken(conjurAuthPayload Sigv4Payload, cfg conjurapi.Config, av authnVars) (authn.AuthnToken, error) {
	// Create Conjur authn-iam payload from AWS Signature v4 Signer
	payload, err := json.Marshal(conjurAuthPayload)
	if err != nil {
		return nil, err
	}

	// Build Conjur URL (Path Escape required on HOST ID to convert / to %2F)
	authnIamUrl := makeRouterURL(cfg.ApplianceURL, "authn-iam", av.conjurServiceId, cfg.Account, url.PathEscape(av.conjurLogin), "authenticate").String()

	// Generate Conjur Client
	var httpClient *http.Client
	if cfg.IsHttps() {
		cert, err := cfg.ReadSSLCert()
		if err != nil {
			return nil, err
		}
		httpClient, err = newHTTPSClient(cert)
		if err != nil {
			return nil, err
		}

	} else {
		httpClient = &http.Client{Timeout: time.Second * 10}
	}

	req, err := http.NewRequest("POST", authnIamUrl, bytes.NewBuffer(payload))
	if err != nil {
		err = fmt.Errorf("error generating the conjur client request : %s", err)
		return nil, err
	}
	req.Header.Add("Content-Type", "text/plain")
	req.Header.Add("Accept", "*/*")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Generate Conjur Authentication Token from Conjur Byte Response
	conjurAuthToken, err := authn.NewToken(body)
	if err != nil {
		err = fmt.Errorf("unable to generate Conjur Token from Conjur Byte Response. Error: %s", err)
		return nil, err
	}

	return conjurAuthToken, nil
}

// NON Exported CONJURAPI Functions
func newHTTPSClient(cert []byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, fmt.Errorf("Can't append Conjur SSL cert")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &http.Client{Transport: tr, Timeout: time.Second * 10}, nil
}

func makeRouterURL(components ...string) routerURL {
	return routerURL(strings.Join(components, "/"))
}

func (url routerURL) String() string {
	return string(url)
}
