package permissions

// TestCaseID -
type TestCaseID string

// PermissionSetTestCases represents one set of permissions that are valid for a set of test ids
type PermissionSetTestCases struct {
	PermissionSet PermissionSet `json:"codes"`
	TestCaseIDs   []TestCaseID  `json:"testIds"`
}

// PermissionTestCollection represents all permissions sets and their respective test id
type PermissionTestCollection []PermissionSetTestCases

// Resolver find minimal codeSet required to satisfy a set Group of permissions (endpoints)
func Resolver(groups []Group) PermissionTestCollection {
	if len(groups) == 0 {
		return nil
	}

	var groupsFound groupSet
	for _, config := range groups {

		if len(groupsFound) == 0 {
			newGroup := config
			groupsFound = append(groupsFound, &newGroup)
			continue
		}

		if config.isSatisfiedByAnyOf(groupsFound) {
			continue
		}

		group, found := groupsFound.firstCompatible(&config)
		if !found {
			newGroup := config
			groupsFound = append(groupsFound, &newGroup)
			continue
		}

		group.add(&config)
	}

	return mapToCodeSets(groups, groupsFound)
}

// StringSliceToTestID -
func StringSliceToTestID(s []string) []TestCaseID {
	tids := make([]TestCaseID, 0)
	for _, v := range s {
		tids = append(tids, TestCaseID(v))
	}
	return tids
}

// StringSliceToPermissionSet -
func StringSliceToPermissionSet(s []string) PermissionSet {
	var cs PermissionSet
	for _, v := range s {
		cs = append(cs, Permission(v))
	}
	return cs

}

// mapToCodeSets maps all permission groups found to results that include test id list
// for each group found
func mapToCodeSets(groups []Group, groupsFound []*Group) []PermissionSetTestCases {
	var codeSets PermissionTestCollection
	for _, groupFound := range groupsFound {
		// find tests that are satisfied by this Group
		for _, group := range groups {
			if group.isSatisfiedBy(groupFound) {
				codeSets.addTestToGroupFound(group, groupFound)
			}
		}
	}
	return codeSets
}

// addTestToGroupFound finds a permission set for a test and adds it to the test id list
// if doesnt find adds a new permission set
func (cs *PermissionTestCollection) addTestToGroupFound(group Group, groupFound *Group) {
	for key, codeSet := range *cs {
		if codeSet.PermissionSet.Equals(groupFound.Included) {
			thisCs := *cs
			thisCs[key] = PermissionSetTestCases{
				PermissionSet: groupFound.Included,
				TestCaseIDs:   append(codeSet.TestCaseIDs, group.TestID),
			}
			return
		}
	}
	// not found codeSet doesnt have this Group
	*cs = append(*cs, PermissionSetTestCases{
		PermissionSet: groupFound.Included,
		TestCaseIDs:   []TestCaseID{group.TestID},
	})
}
