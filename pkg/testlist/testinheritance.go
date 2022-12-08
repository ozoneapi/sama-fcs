package testlist

/*
	What needs to be done to implement testdefinition inheritance?

	Inherits -> testdefintion?
	Generation time, or runtime?
	Generation time - inherit - name....
	Otherwise its going to be really difficult to figure out what's going on.

	Process Tests - one by one. add to generatedTestList
	If 'inherits' - look for 'id' in genratedTestList
		if not present - fail
		if present
			clone existing test definition
			then add to it - simply overwriting any previous settings
			sanity check for incompatible changes? not initially ...
	Single inheritance only
		i.e. c inherits from b which could inherit from a
		not c interits from b and c also interits from a - c has no knowledge of a

	What needs to be done to implement jwt annotation/content type
		outgoing ->
			bodyData modification.
			sig algorithm
			signing key
			claims requried
			wrap message/data
			verify sign
		incoming
			<-- responseData
			jwks stored ... grab at startup if sig checks required
			sig algorithm


	What needs to be done to implement signatures
		(already have signatures in this)
		ensure jwks endpoint -> ensure can get pub cert
		ensure signing key (pub key is not required)

*/
