package testlist

import (
	"fmt"
	"strings"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
)

const accountsPath = "file://manifests/ob_3.1_accounts_transactions_fca.json"
const paymentsPath = "file://manifests/ob_3.1_payment_fca.json"
const cbpiiPath = "file://manifests/ob_3.1_cbpii_fca.json"

type apiTests struct {
	APIType     spec.Type
	PathtoTests string
}

// GenerateTestCaseListCSV - dump out test cases
func GenerateTestCaseListCSV() {
	apis := []apiTests{{"accounts", accountsPath}, {"payments", paymentsPath}, {"cbpii", cbpiiPath}}

	var values []interface{}
	values = append(values, "accounts_v0.0.0", "payments_v0.0.0", "cbpii_v0.0.0")

	fmt.Println("Resource,TestCase Id,Method,Path,Condition,Version,Schema,Sig,Description")
	for _, apix := range apis {
		specType, specVersion, err := spec.GetVersionType(string(apix.APIType), "0.0.0")

		scripts, _, err := LoadReferenceData(specType, specVersion, apix.PathtoTests)
		if err != nil {
			fmt.Printf("Error on loadGenerationResources %v", err)
			return
		}

		for _, v := range scripts.TestDefinitions {
			description := strings.Replace(v.Description, ",", "", -1)
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n", v.Resource, v.ID, strings.ToUpper(v.Method),
				v.URI, v.URIImplemenation, v.APIVersion, v.SchemaCheck, v.ValidateSignature, description)
		}
	}
}
