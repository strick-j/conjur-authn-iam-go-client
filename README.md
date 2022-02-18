# conjur-authn-iam-go-client

A Golang package for generating a Conjur Client based via the [authn-iam authenticator](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/AWS_IAM_Authenticator.htm).

## Installation
```
go get -u github.com/strick-j/conjur-authn-iam-go-client
```

## Usage

### Example

For a full examples of usage, please see:
1. [EC2 IAM Role](examples/ec2role_example.go)
2. [Assume Role](examples/assumerole_example.go)
3. [Profile](examples/profile_example.go)
4. [Static](examples/static_example.go)

```golang
import "github.com/strick-j/conjur-authn-iam-go-client"
```

### func NewConjurIamClient

```golang
func (p ConjurIamParams) NewConjurIamClient() (*conjurapi.Client, error)
```

`conjurIamClient.NewConjurIamClient` takes takes a struct containing specific AWS IAM Parameters. Based on the IamAuthMethod and supporting parameters a Conjur Client is created. 

### type ConjurIamParams

```golang
type ConjurIamParams struct {
	IamAuthMethod   string // IAM IamAuthMethodod: "static", "iamrole", "assumerole", "profile"
	Profile         string // AWS Profile (e.g. Default)
	RoleArn         string // AWS Role ARN (required for assumeRole)
	AccessKey       string // AWS Access Key (Required for static)
	SecretKey       string // AWS Secret Key (Required for static)
	SessionToken    string // AWS Session Token (Optional for static)
}
```

`conjurIamClient.ConjurIamParams` must be provided when calling the NewConjurIamClient function. The parameters specify the method for AWS Role Assumption. Each AWS Role Assumption method has unique requirements.

|Method|Short Description|Required ConjurIamParams|
|ec2role|Uses the role assigned to the host|IamAuthMethod|
|assumerole|Attempts to use host defaults (e.g. Env, ~/.aws/credentials)|IamAuthMethod, RoleArn|
|profile|Uses credentials assigned to the profile to assume role|IamAuthMethod, Profile, RoleArn|
|static|Uses static credentials to assume role (testing only)|IamAuthMethod, RoleArn, AccessKey, SecretKey|

### Additional Requirements

This package leverages two other primary packages [aws-go-sdk-v2](https://github.com/aws/aws-sdk-go-v2) and [conjur-api-go](https://github.com/cyberark/conjur-api-go).

Specifically, with the Conjur API the `conjurapi.LoadConfig` function is used to obtain required Conjur variables. These include required variables such as the Conjur Appliance URL and Conjur Account. If these are not set properly the Conjur Client will not be generated.

The following must be set in order for the package to run appropriately:
1. CONJUR_AUTHN_IAM_SERVICE_ID - Environment Variable (e.g. prod)
2. CONJUR_AUTHN_LOGIN - Enviornment Variable or Config File (.conjurrc/.netrc) (e.g. host/policy/prefix/id)
3. CONJUR_ACCOUNT - Environment Variable or Config File (.conjurrc/.netrc) (e.g. default
4. CONJUR_APPLIANCE_URL - Environment Variable or Config File (.conjurrc/.netrc) (e.g. https://yourconjurhost.yourdomain.com)

