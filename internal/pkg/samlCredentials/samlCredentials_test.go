package samlCredentials

import (
	"errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResolveInvalidArgs(t *testing.T) {
	samlInfo, err := Resolve("", "", "")

	assert.Nil(t, samlInfo)
	assert.Equal(t, errors.New("either alias or account and role is required"), err)
}

func TestResolveAccountRole(t *testing.T) {
	expected := &SamlCredentials{
		AccountID: "dev-account",
		RoleName:  "dev-role",
	}

	samlInfo, err := Resolve("", "dev-account", "dev-role")

	assert.Nil(t, err)
	assert.Equal(t, expected, samlInfo)
}

func TestResolveAlias(t *testing.T) {
	expected := &SamlCredentials{
		AccountID: "dev-account",
		RoleName:  "dev-role",
	}

	aliasMock := map[string]string{
		"account": "dev-account",
		"role":    "dev-role",
	}

	viper.Set("saml.alias.dev", aliasMock)

	samlInfo, err := Resolve("dev", "account", "role")

	assert.Nil(t, err)
	assert.Equal(t, expected, samlInfo)
}
