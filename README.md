# ewcli

ewcli it's a small tool to simplify some day to day tasks such as getting
environment variables with AWS credentals from an AWS SAML assertion.

## Usage

ewcli it's based on subcommands. Currently available: `aws saml` and `athq`.

### ewcli aws saml

```
Usage:
  ewcli aws saml [flags]

Flags:
  -l, --alias string             Pass a saml alias name from the config
  -h, --help                     help for saml
      --print-env-creds          Print Credentials as Environment Variables
  -a, --saml-account-id string   Pass an AWS Account ID
  -f, --saml-file string         Pass a path to the file that contains SAML Assertion (default "/tmp/saml")
      --saml-role-name string    Pass an AWS IAM Role Name

Global Flags:
      --config string   config file (default is $HOME/.ewcli.yaml)
  -r, --region string   Pass an AWS region (default "us-east-1")
```

#### Example - with account and role

``` sh
> ewcli aws saml -f /tmp/saml --saml-account-id 123456789 --saml-role-name GoogleReadOnlyAccess --print-env-creds                                                                                  
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

#### Example - with alias

Be sure to have the alias configured on your `.ewcli.yaml`
```yaml
saml:
  alias:
    'admin-dev':
      account: 123456
      role: users/admin
```

And execute it passing the alias flag:

``` sh
> ewcli aws saml -f /tmp/saml --alias admin-dev --print-env-creds                                                                                  
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

### ewcli athq

Run an Athena query synchronously and print the result rows. Designed to
be dropped into an AWS CloudShell session (e.g. `wget` the binary from a
release and run it directly) so the active console credentials are used.

```
Usage:
  ewcli athq [query] [flags]

Flags:
  -c, --catalog string           Athena data catalog (optional)
  -d, --database string          Athena database (optional)
  -f, --format string            Output format: tsv or csv (default "tsv")
  -o, --output-location string   S3 output location, e.g. s3://bucket/prefix/ (optional if workgroup has one)
      --poll-interval duration   How often to poll the query status (default 500ms)
  -r, --region string            AWS region (defaults to AWS_REGION / shared config)
  -w, --workgroup string         Athena workgroup (default "primary")
```

#### Example

``` sh
> ewcli athq -d walterdb "SELECT * FROM AwsCatalog.walterdb.waltertable;"
col1	col2	col3
...
```

If your workgroup does not have a default result location configured,
pass one explicitly:

``` sh
> ewcli athq -o s3://my-bucket/athena-results/ "SELECT 1"
```
