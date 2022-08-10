package samlCredentials

import (
	"errors"
	"fmt"
	"github.com/spf13/viper"
)

type aliasConfig struct {
	Account string `yaml:"account"`
	Role    string `yaml:"role"`
}

type SamlCredentials struct {
	AccountID string
	RoleName  string
}

func Resolve(alias string, account string, role string) (samlInfo *SamlCredentials, err error) {
	if alias == "" && (account == "" || role == "") {
		return nil, errors.New(fmt.Sprintf("either alias or account and role is required"))
	}

	if alias != "" {
		return resolveAlias(alias)
	}

	return &SamlCredentials{
		AccountID: account,
		RoleName:  role,
	}, nil
}

func resolveAlias(alias string) (samlInfo *SamlCredentials, err error) {
	aliasConfigKey := fmt.Sprintf("saml.alias.%s", alias)

	if !viper.IsSet(aliasConfigKey) {
		return nil, errors.New(fmt.Sprintf("Alias '%s' not found on configuration", alias))
	}

	aliasConfig := &aliasConfig{}
	err = viper.UnmarshalKey(aliasConfigKey, aliasConfig)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to parse alias '%s' config", alias))
	}

	samlInfo = &SamlCredentials{
		AccountID: aliasConfig.Account,
		RoleName:  aliasConfig.Role,
	}

	return samlInfo, nil
}
