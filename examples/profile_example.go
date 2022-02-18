// IAM Authentication Method - "profile"
//
// "profile" requires a configured AWS Profile
// For this method to work you must have a profile configured
// and credentials should be in either ~/.aws/config or
// ~/.aws/credentials.
//
// The credentials in the provided profile should be authorized
// to assume the provided AWS Role Arn.
//
// Intially, the profile credentials are used to attempt role
// assumption of the provided Role Arn. If role assumption
// is successful the aws-sdk-go-v2/service/sts package is used to
// create an AWS STS client and then the aws-sdk-go-v2/credentials/stscreds
// package is used to create a credential provider. After provider
// creation, the aws-sdk-go-v2/services/signer/v4 package to
// obtain the Sig v4 Signature required to obtain Conjur
// Session Token. The final step is creating a Conjur Client
// based on the returned Session Token.
//
// Note: The credentials stored in the ~/.aws/config or
// ~/.aws/credentials file should be protected appropriately

package examples

import (
	"fmt"

	conjurIamClient "github.com/strick-j/conjur-authn-iam-go-client"
)

func ProfileAuthSecretRetrieve() {
	variableId := "policy/path/variable-id"

	// Required Parameters for static method
	// IamAuthMethod, AccessKey, SecretKey, RoleArn
	p := &conjurIamClient.ConjurIamParams{
		IamAuthMethod: "static",
		AccessKey: "<AWS_ACCESS_KEY_ID>", // Required
		SecretKey: "<AWS_SECRET_KEY_ID>", // Required
		SessionToken: "z,AWS_SESSION_TOKEN>", // Optional
		RoleArn:  "arn:aws:iam::<aws account number>:role/<aws role name>", // Required
	}

	// Retrieve Conjur Client based on IAM Role
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