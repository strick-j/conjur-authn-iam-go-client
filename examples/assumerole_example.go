// IAM Authentication Method - "assumerole"
//
// "assumerole" attempts to load nitial credentials
// SDK's default credential chain (e.g. the os environment,
// shared credentials (~/.aws/credentials), or EC2 Instance
// Role.
//
// The credentials stored in in the provided should be authorized
// to assume the provided AWS Role Arn.
//
// The credentials provided are used to attempt role
// assumption of the provided Role Arn. If role assumption
// is successful, the aws-sdk-go-v2/service/sts package is used to
// create a client and then the aws-sdk-go-v2/credentials/stscreds
// package is used to create a credential provider. The provider
// is used to obtain temporary AWS Credentials which are
// used by the aws-sdk-go-v2/services/signer/v4 package to
// obtain the Sig v4 Signature required to obtain Conjur
// Session Token. The final step is creating a Conjur Client
// based on the returned Session Token.
//
// Note: This method is inherently insecure and is recommended
// for testing purposes only.

package examples

import (
	"fmt"

	conjurIamClient "github.com/strick-j/conjur-authn-iam-go-client"
)

func AssumeRoleAuthSecretRetrieve() {
	variableId := "policy/path/variable-id"

	// IamAuthMethod: "assumerole"
	// Required Parameters: IamAuthMethod, RoleArn
	p := &conjurIamClient.ConjurIamParams{
		IamAuthMethod: "assumerole",
		RoleArn:       "arn:aws:iam::<AWS_ACCOUNT_NUMBER>:role/<AWS_ROLE_NAME>", // Required
	}

	// Retrieve Conjur Client based on IAM Role assumed using
	// discovered credentials (env, profile, etc...).
	// If successful returns Conjur IAM Client, else returns error
	conjurClient, err := p.NewConjurIamClient()
	if err != nil {
		fmt.Printf("error creating client : %s", err)
	}

	// Retrieve Secret using Conjur Client
	secretValue, err := conjurClient.RetrieveSecret(variableId)
	if err != nil {
		fmt.Printf("error retriveing secret : %s", err)
	}
	fmt.Printf("Secret Value: %s", string(secretValue))
}
