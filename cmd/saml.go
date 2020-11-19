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
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Run: func(cmd *cobra.Command, args []string) {
	// 	fmt.Println("saml called")
	// },
	RunE: runSaml,
}

// SamlFlags holds flags that are used by saml subcommand
type SamlFlags struct {
	samlPath      string
	samlAccountID string
	samlRoleName  string
	printEnvCreds bool
}

var (
	samlFlags     SamlFlags
	samlAssertion []byte
	samlRoleArn   string
	samlIdpArn    string
)

const (
	errMsgOpenSamlAssertion = "IDP not found in SAML assertion"
)

func init() {
	awsCmd.AddCommand(samlCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// samlCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// samlCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	samlCmd.Flags().StringVarP(&samlFlags.samlPath, "saml-file", "f", "/tmp/saml", "Pass a path to the file that contains SAML Assertion")
	samlCmd.Flags().StringVarP(&samlFlags.samlAccountID, "saml-account-id", "a", "", "Pass an AWS Account ID")
	samlCmd.Flags().StringVarP(&samlFlags.samlRoleName, "saml-role-name", "", "", "Pass an AWS IAM Role Name")
	samlCmd.Flags().BoolVarP(&samlFlags.printEnvCreds, "print-env-creds", "", false, "Print Credentials as Environment Variables")
}

func runSaml(cmd *cobra.Command, args []string) error {
	return runSamlCommand(args, samlFlags)
}

func runSamlCommand(args []string, samlFlags SamlFlags) error {
	// Read SAML from file
	samlAssertion, err := ioutil.ReadFile(samlFlags.samlPath)
	if err != nil {
		log.Printf("ERROR: Unable to open %s: %v", samlFlags.samlPath, err.Error())
		return err
	}
	// Get AccountID from SAML request.
	samlIdpArn, err := getIDPFromSAMLAssertion(samlFlags.samlAccountID, samlAssertion)
	if err != nil {
		log.Printf("Please validate content of file %s: %v", samlFlags.samlPath, err.Error())
		return err
	}
	samlRoleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", samlFlags.samlAccountID, samlFlags.samlRoleName)
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
