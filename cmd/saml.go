/*
Copyright © 2020 Walter Vargas <waltervargas@linux.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"github.com/waltervargas/ewcli/internal/pkg/samlCredentials"
	"io/ioutil"
	"log"
	"regexp"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
)

// samlCmd represents the saml command
var samlCmd = &cobra.Command{
	Use:   "saml",
	Short: "aws saml subcommand deals with AWS IAM AssumeRole with SAML",
	Long:  `aws saml subcommand deals with AWS IAM AssumeRole with SAML`,
	RunE:  runSaml,
}

// SamlFlags holds flags that are used by saml subcommand
type SamlFlags struct {
	alias         string
	samlPath      string
	samlAccountID string
	samlRoleName  string
	printEnvCreds bool
}

var (
	samlFlags SamlFlags
)

const (
	errMsgOpenSamlAssertion = "IDP not found in SAML assertion"
)

func init() {
	awsCmd.AddCommand(samlCmd)

	samlCmd.Flags().StringVarP(&samlFlags.alias, "alias", "l", "", "Pass a saml alias name from the config")
	samlCmd.Flags().StringVarP(&samlFlags.samlAccountID, "saml-account-id", "a", "", "Pass an AWS Account ID")
	samlCmd.Flags().StringVarP(&samlFlags.samlRoleName, "saml-role-name", "", "", "Pass an AWS IAM Role Name")
	samlCmd.Flags().StringVarP(&samlFlags.samlPath, "saml-file", "f", "/tmp/saml", "Pass a path to the file that contains SAML Assertion")
	samlCmd.Flags().BoolVarP(&samlFlags.printEnvCreds, "print-env-creds", "", false, "Print Credentials as Environment Variables")
}

func runSaml(_ *cobra.Command, args []string) error {
	return runSamlCommand(args, samlFlags)
}

func runSamlCommand(_ []string, samlFlags SamlFlags) error {
	// Resolve account and role to assume
	credentials, err := samlCredentials.Resolve(samlFlags.alias, samlFlags.samlAccountID, samlFlags.samlRoleName)
	if err != nil {
		log.Printf("ERROR: Failed to process saml info: %v", err.Error())
		return err
	}

	log.Printf("Using : %s { %s/%s }", samlFlags.alias, credentials.AccountID, credentials.RoleName)

	// Read SAML from file
	samlAssertion, err := ioutil.ReadFile(samlFlags.samlPath)
	if err != nil {
		log.Printf("ERROR: Unable to open %s: %v", samlFlags.samlPath, err.Error())
		return err
	}
	// Get AccountID from SAML request.
	samlIdpArn, err := getIDPFromSAMLAssertion(credentials.AccountID, samlAssertion)
	if err != nil {
		log.Printf("Please validate content of file %s: %v", samlFlags.samlPath, err.Error())
		return err
	}
	samlRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", credentials.AccountID, credentials.RoleName)
	samlOutput, err := assumeRoleWithSAML(samlAssertion, samlIdpArn, samlRoleArn)
	if err != nil {
		return err
	}
	envVars, err := getENVFromSAML(samlOutput)
	if err != nil {
		return err
	}

	if samlFlags.printEnvCreds {
		fmt.Println(envVars)
	}
	return nil
}

func getIDPFromSAMLAssertion(accountID string, samlAssertion []byte) (string, error) {
	sDec, _ := b64.StdEncoding.DecodeString(string(samlAssertion))
	pattern := fmt.Sprintf(`arn\:aws\:iam\::%s:saml-provider/\w+`, accountID)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(string(sDec))
	if len(match) > 0 {
		return match[0], nil
	}
	return "", errors.New(errMsgOpenSamlAssertion)
}

func assumeRoleWithSAML(samlAssertion []byte, samlIdpArn string, samlRoleArn string) (*sts.AssumeRoleWithSAMLOutput, error) {
	// Get credentials via SAML
	svc := sts.New(session.New())
	samlInput := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(3600), // TODO: Parameter with default value
		PrincipalArn:    aws.String(samlIdpArn),
		RoleArn:         aws.String(samlRoleArn),
		SAMLAssertion:   aws.String(string(samlAssertion)),
	}
	samlOutput, err := svc.AssumeRoleWithSAML(samlInput)
	if err != nil {
		return nil, err
	}

	return samlOutput, nil
}

func getENVFromSAML(samlOutput *sts.AssumeRoleWithSAMLOutput) (string, error) {
	tmpl := `export AWS_ACCESS_KEY_ID={{.Credentials.AccessKeyId}}
export AWS_SECRET_ACCESS_KEY={{.Credentials.SecretAccessKey}}
export AWS_SESSION_TOKEN={{.Credentials.SessionToken}}
`
	t, err := template.New("t").Parse(tmpl)
	if err != nil {
		return "", err
	}

	var output bytes.Buffer
	err = t.Execute(&output, *samlOutput)
	if err != nil {
		return "", err
	}

	return output.String(), nil
}
