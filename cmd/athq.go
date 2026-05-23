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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/spf13/cobra"
)

// AthqFlags holds flags for the athq subcommand.
type AthqFlags struct {
	database       string
	catalog        string
	workgroup      string
	outputLocation string
	region         string
	pollInterval   time.Duration
	format         string
}

var athqFlags AthqFlags

var athqCmd = &cobra.Command{
	Use:   "athq [query]",
	Short: "Run an Athena query and print the results",
	Long: `athq runs an Athena query synchronously and prints the result rows.

Credentials and region are resolved from the standard AWS chain
(environment, shared config, instance/role). When run inside AWS
CloudShell the active console credentials are used automatically.

If --output-location is not provided, the configured workgroup must
have a default result location set.`,
	Args: cobra.ExactArgs(1),
	RunE: runAthq,
}

func init() {
	rootCmd.AddCommand(athqCmd)

	athqCmd.Flags().StringVarP(&athqFlags.database, "database", "d", "", "Athena database (optional)")
	athqCmd.Flags().StringVarP(&athqFlags.catalog, "catalog", "c", "", "Athena data catalog (optional)")
	athqCmd.Flags().StringVarP(&athqFlags.workgroup, "workgroup", "w", "primary", "Athena workgroup")
	athqCmd.Flags().StringVarP(&athqFlags.outputLocation, "output-location", "o", "", "S3 output location, e.g. s3://bucket/prefix/ (optional if workgroup has one)")
	athqCmd.Flags().StringVarP(&athqFlags.region, "region", "r", "", "AWS region (defaults to AWS_REGION / shared config)")
	athqCmd.Flags().DurationVar(&athqFlags.pollInterval, "poll-interval", 500*time.Millisecond, "How often to poll the query status")
	athqCmd.Flags().StringVarP(&athqFlags.format, "format", "f", "tsv", "Output format: tsv or csv")
}

func runAthq(_ *cobra.Command, args []string) error {
	return runAthqQuery(os.Stdout, os.Stderr, args[0], athqFlags)
}

func runAthqQuery(stdout, stderr io.Writer, query string, flags AthqFlags) error {
	sep, err := separatorFor(flags.format)
	if err != nil {
		return err
	}

	awsCfg := aws.NewConfig()
	if flags.region != "" {
		awsCfg = awsCfg.WithRegion(flags.region)
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            *awsCfg,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return fmt.Errorf("aws session: %w", err)
	}
	svc := athena.New(sess)

	startInput := &athena.StartQueryExecutionInput{
		QueryString: aws.String(query),
	}
	if flags.workgroup != "" {
		startInput.WorkGroup = aws.String(flags.workgroup)
	}
	if flags.database != "" || flags.catalog != "" {
		ctx := &athena.QueryExecutionContext{}
		if flags.database != "" {
			ctx.Database = aws.String(flags.database)
		}
		if flags.catalog != "" {
			ctx.Catalog = aws.String(flags.catalog)
		}
		startInput.QueryExecutionContext = ctx
	}
	if flags.outputLocation != "" {
		startInput.ResultConfiguration = &athena.ResultConfiguration{
			OutputLocation: aws.String(flags.outputLocation),
		}
	}

	start, err := svc.StartQueryExecution(startInput)
	if err != nil {
		return fmt.Errorf("start query: %w", err)
	}
	qid := aws.StringValue(start.QueryExecutionId)
	fmt.Fprintf(stderr, "ewcli: athena query %s\n", qid)

	if err := waitForQuery(svc, qid, flags.pollInterval); err != nil {
		return err
	}

	return printResults(stdout, svc, qid, sep)
}

func separatorFor(format string) (string, error) {
	switch strings.ToLower(format) {
	case "", "tsv":
		return "\t", nil
	case "csv":
		return ",", nil
	default:
		return "", fmt.Errorf("unsupported format %q (use tsv or csv)", format)
	}
}

func waitForQuery(svc *athena.Athena, qid string, poll time.Duration) error {
	for {
		out, err := svc.GetQueryExecution(&athena.GetQueryExecutionInput{
			QueryExecutionId: aws.String(qid),
		})
		if err != nil {
			return fmt.Errorf("get query execution: %w", err)
		}
		state := aws.StringValue(out.QueryExecution.Status.State)
		switch state {
		case athena.QueryExecutionStateSucceeded:
			return nil
		case athena.QueryExecutionStateFailed, athena.QueryExecutionStateCancelled:
			reason := aws.StringValue(out.QueryExecution.Status.StateChangeReason)
			return fmt.Errorf("query %s: %s", state, reason)
		}
		time.Sleep(poll)
	}
}

func printResults(w io.Writer, svc *athena.Athena, qid, sep string) error {
	input := &athena.GetQueryResultsInput{QueryExecutionId: aws.String(qid)}
	return svc.GetQueryResultsPages(input, func(page *athena.GetQueryResultsOutput, _ bool) bool {
		for _, row := range page.ResultSet.Rows {
			cells := make([]string, len(row.Data))
			for i, d := range row.Data {
				cells[i] = aws.StringValue(d.VarCharValue)
			}
			fmt.Fprintln(w, strings.Join(cells, sep))
		}
		return true
	})
}
