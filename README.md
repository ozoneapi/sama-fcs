# SAMA OzoneAPI  Functional Conformance Suite
Based on the [OBIE Conformance Suite](https://github.com/OpenBankingUK/conformance-suite)

Please read the [License](LICENSE.TXT)

---
## LAYOUT OF FILES
---
## Specification files
The specifications supported by the conformance tool are found under the directory `resources/specs`

* `ksa.v2022.11.1\KSA.AccountInformationServices.yaml`
* `ksa.V2022.11.1\KSA.LetterOfGuarantee.yaml`

---
## Layout of tests.

The tests run by the conformance suite live in the `resources/testdefs` directory

`ksa_1.0_accounts_transactions.json`
* The SAMA AIS tests are in this file 

`ksa_1.0_letter_of_guarantee.json`
* The SAMA Letter of Guarantee tests are in this file 

The tests are supported by two other files.

`ksa_assertions.json` 

* contains descriptions of http status codes used by the tests
* contains json error response bodys used by the tests to check that errors are of the correct format

`data.json`
* contains http request body templates
* the templates used as-is, and also reused with test variables inserted

## Structure of the Tests
High level tests are defined in the ksa_1.0 accounts and letters file. 
The high level definitions contain descriptions of the tests, endpoints under test, parameters to the tests in the form of http headers, url query strings and body data. 
Criteria for test success is defined in the `asserts` and `asserts_one_of` sections. `asserts_one_of` allows a test to have a number of valid mutually exclusive results. Each name in the `asserts` section refers to a defintion in the `ksa_assertions.json` file. Definitions in the assertions file can refer to any aspect of a response payload, included specific values for headers, or json data files in the response payload via literal or regular expression matching.

Request bodies can be included in test requests via the `data.json` file templates. Templates can be literal, use existing parameters, or use the results of previous tests.

Schema checking can switched on and off for each particualar test. The checking is normally on and provides thorough introspection into all the response header fields, body fields and http status codes, so ensure that they exactly match the definitions in the openapi3 schema. 

The tool takes the openapi3 schema, testdefinitions, template data, assertions and additional user input that arises from the configuration file. It uses these artifacts to generate the low level test cases which are then run sequentially.

Over time the tests naturally change, expand and improve as feedback from implementors is received and the specification matures to clarify its original intentions.

---
### Build and Run instructions

```
make init # requires golang 1.19 and nodejs > v9, < v11
make build  
make run  # wait for node ui to start before hitting http://localhost:8443
```