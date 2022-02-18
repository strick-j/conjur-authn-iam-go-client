// IAM Authentication Method - "ec2role"
//
// "ec2role" requires requires the ec2 host to have an IAM
// role assigned. 
//
// The aws-sdk-go-v2/credentials/ec2rolecreds package to 
// create an EC2 IMDS Provider. The EC2 IMDS provider
// is used to obtain temporary AWS Credentials which are
// used by the aws-sdk-go-v2/services/signer/v4 package to
// obtain the Sig v4 Signature required to obtain Conjur
// Session Token. The final step is creating a Conjur Client
// based on the returned Session Token.

package examples

import (
	"fmt"

	conjurIamClient "github.com/strick-j/conjur-authn-iam-go-client"
)

func Ec2RoleAuthSecretRetrieve() {
	variableId := "policy/path/variable-id"

	
	p := &conjurIamClient.ConjurIamParams{
		IamAuthMethod: "ec2role",
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
