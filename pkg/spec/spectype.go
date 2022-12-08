package spec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
)

// Type - specification type
type Type string

// Concerte Spec Types
const (
	Unknown     = "unknown"
	KsaAccount  = "ksa_account"
	KsaLetter   = "ksa_letter"
	ObieAccount = "obie_account"
	ObiePayment = "obie_payment"
	ObieCBPII   = "obie_cbpii"
	ObieVRP     = "obie_vrp"

	ksaAccountPath  = "file://testdefs/ksa_1.0_accounts_transactions.json"
	ksaLetterPath   = "file://testdefs/ksa_1.0_letter_of_guarantee.json"
	obieAccountPath = "file://testdefs/ob_3.1_accounts_transactions_fca.json"
	obiePaymentPath = "file://testdefs/ob_3.1_payment_fca.json"
	obieCBPIIPath   = "file://testdefs/ob_3.1_cbpii.json"
	obieVRPPath     = "file://testdefs/ob_3.1_varriable_recurring_payment.json"
)

// GetTestDefinitionsPath - return the path to manifest file listing the pool of tests
// for each specification
func GetTestDefinitionsPath(spec Type) (string, error) {
	switch spec {
	case KsaAccount:
		return ksaAccountPath, nil
	case KsaLetter:
		return ksaLetterPath, nil
	case ObieAccount:
		return obieAccountPath, nil
	case ObiePayment:
		return obiePaymentPath, nil
	case ObieCBPII:
		return obieCBPIIPath, nil
	case ObieVRP:
		return obieVRPPath, nil
	default:
		return "", errors.New("Can't find Test Definition path for specType: " + spec.String())
	}
}

// GetVersionType -
func GetVersionType(apiName string, apiVersion string) (Type, semver.Version, error) {
	ver := semver.Version{}
	specType, err := GetSpecType(apiName)
	if err != nil {
		return specType, ver, err
	}
	ver, err = GetSemanticVersion(apiVersion)
	if err != nil {
		return specType, ver, err
	}
	return specType, ver, nil
}

// GetSpecType - Classifies the Specification based on Spec Name in Discovery File
func GetSpecType(specName string) (Type, error) {
	// *** All supported Specs Need to be listed here ***
	if strings.Contains(specName, "KSA") && strings.Contains(specName, "Account") {
		return KsaAccount, nil
	}
	if strings.Contains(specName, "KSA") && strings.Contains(specName, "Letter") {
		return KsaLetter, nil
	}
	if strings.Contains(specName, "OBIE") && strings.Contains(specName, "Account") {
		return ObieAccount, nil
	}
	if strings.Contains(specName, "OBIE") && strings.Contains(specName, "Payment") {
		return ObiePayment, nil
	}
	if strings.Contains(specName, "OBIE") && strings.Contains(specName, "CBPII") {
		return ObieCBPII, nil
	}
	if strings.Contains(specName, "OBIE") && strings.Contains(specName, "VRP") {
		return ObieVRP, nil
	}
	return Unknown, errors.New("Unknown specification:  `" + specName + "`")
}

func (s Type) String() string {
	switch s {
	case KsaAccount:
		return KsaAccount
	case KsaLetter:
		return KsaLetter
	case ObieAccount:
		return ObieAccount
	case ObiePayment:
		return ObiePayment
	case ObieCBPII:
		return ObieCBPII
	case ObieVRP:
		return ObieVRP
	}
	return Unknown
}

// GetSemanticVersion -
// Accepts a random version string, maps it to a string which
// fits the internal semantic versioning model
func GetSemanticVersion(ver string) (semver.Version, error) {
	versionString := ""

	switch ver {
	case "2022.11.01-final", "v2022.11.01-final", "v2022.11.1-final":
		versionString = "2022.11.01"

	case "v3.1.10", "3.1.10":
		versionString = "3.1.10"

	case "v3.1.9", "3.1.9":
		versionString = "3.1.9"

	case "v3.1.8", "3.1.8":
		versionString = "3.1.8"
	}

	version, err := semver.ParseTolerant(versionString)
	if err != nil {
		logrus.WithError(err).Error("parsing spec version: " + versionString)
		return version, errors.New("Unsupported Spec Version Number: `" + versionString + "`")
	}

	return version, nil
}

// GetSpecFilePathPattern -
func GetSpecFilePathPattern(stype Type, ver semver.Version) (string, error) {
	var filename string

	version := fmt.Sprintf("%d.%d.%d", ver.Major, ver.Minor, ver.Patch)
	switch stype {
	case KsaAccount:
		filename = "specs/ksa.v" + version + "/KSA.AccountInformationServices.yaml"
	case KsaLetter:
		filename = "specs/ksa.v" + version + "/KSA.LetterOfGuarantee.yaml"
	case ObieAccount:
		filename = "specs/v" + version + "/account-info-openapi.json"
	case ObiePayment:
		filename = "specs/v" + version + "/payment-initiation-openapi.json"
	case ObieCBPII:
		filename = "specs/v" + version + "/confirmation-funds-openapi.json"
	case ObieVRP:
		filename = "specs/v" + version + "/variable-recurring-payments-openapi.json"
	default:
		return "", errors.New("Cannot get Spec File Path for " + stype.String() + ":" + ver.String())
	}
	return filename, nil
}

// BaseURLID String to index baseURL for a spec in the context
// ctx.PUT(stype.BaseURLID, "https://rs1.lab.openbanking.sa/openbanking/2022.11.1-final")
// ctx.GET(stype.BaseURLID)
func (s *Type) BaseURLID() string {
	return "baseUrl_" + s.String()
}
