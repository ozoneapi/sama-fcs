package permissions

// Permission is a string representing a OB access permission
type Permission string

// PermissionSet is a set of OB Permission permissions
type PermissionSet []Permission

// NoPermissionSet represents empty or no permissions set
func NoPermissionSet() PermissionSet {
	return PermissionSet{}
}

// Has check if a set Has a Permission
func (p PermissionSet) Has(searchPermission Permission) bool {
	for _, permission := range p {
		if permission == searchPermission {
			return true
		}
	}
	return false
}

// HasAll check is a set has all codes in other set
func (p PermissionSet) HasAll(otherSet PermissionSet) bool {
	for _, code := range otherSet {
		if !p.Has(code) {
			return false
		}
	}
	return true
}

// Equals check if 2 sets have the SAME codes
func (p PermissionSet) Equals(otherSet PermissionSet) bool {
	if len(otherSet) != len(p) {
		return false
	}

	if !p.HasAll(otherSet) {
		return false
	}

	return true
}

// HasAny checks if has any of the codes of other set
func (p PermissionSet) HasAny(otherSet PermissionSet) bool {
	for _, code := range otherSet {
		if p.Has(code) {
			return true
		}
	}
	return false
}

// Union - returns union of 2 sets
func (p PermissionSet) Union(otherSet PermissionSet) PermissionSet {
	union := PermissionSet{}
	for _, permission := range p {
		if !union.Has(permission) {
			union = append(union, permission)
		}
	}
	for _, permission := range otherSet {
		if !union.Has(permission) {
			union = append(union, permission)
		}
	}
	return union
}
