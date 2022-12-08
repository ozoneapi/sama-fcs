package resources

import "embed"

// Specs - all the specs
//
//go:embed specs
var Specs embed.FS

// Testdefs -
// testcase templates for each api
// assert files
// body templates
//
//go:embed testdefs
var Testdefs embed.FS
