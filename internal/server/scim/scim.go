// Package scim is the wire format of SCIM 2.0, and nothing else.
//
// Types, marshalling, filters and errors. It holds no store, evaluates no
// policy and makes no decisions: the handlers in internal/server/httpapi do
// that, so what a provisioning client is allowed to do is decided in the same
// place as everything else rather than in a protocol package.
//
// The shape is RFC 7643 (schema) and RFC 7644 (protocol). Both are large, and
// this implements the part identity providers actually send — Users, Groups,
// the discovery documents they fetch first, and the filters they reconcile
// with. What is missing is missing on purpose and listed in
// ServiceProviderConfig, which is the mechanism the specification provides for
// saying so: a client reads it and adapts, rather than discovering a gap from a
// 501 in the middle of a synchronisation.
package scim

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Schema URNs, which SCIM uses the way other protocols use a version number.
const (
	SchemaUser          = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError         = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaServiceConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// ContentType is what SCIM sends and accepts.
//
// Not application/json. Some clients check, and a provider answering with the
// wrong one has failed the first thing a strict implementation tests.
const ContentType = "application/scim+json"

// Meta is the common resource envelope.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`

	// Version is an entity tag. Absent here, deliberately: Cardinal has no
	// per-row version to report, and a fabricated one would break the
	// conditional requests a client would then believe it could make.
	Version string `json:"version,omitempty"`
}

// Name is SCIM's structured name. Cardinal keeps one display name, so only
// formatted is ever populated — the sub-fields are parsed out of a person by
// their employer, and guessing which half of "Ada Lovelace" is a surname is not
// something a directory should do silently.
type Name struct {
	Formatted string `json:"formatted,omitempty"`
}

// Email is one address. Cardinal keeps a single one, so a client sending three
// gets the primary — or the first, when none is marked.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Ref is a pointer to another resource, used for group membership.
type Ref struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// User is a SCIM user resource.
type User struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`

	Name        *Name   `json:"name,omitempty"`
	DisplayName string  `json:"displayName,omitempty"`
	Emails      []Email `json:"emails,omitempty"`

	// Active is how SCIM says enabled. A client deprovisioning somebody sends
	// active:false far more often than it sends DELETE, because most identity
	// providers treat removal as reversible and deletion as not.
	Active bool `json:"active"`

	Groups []Ref `json:"groups,omitempty"`
	Meta   Meta  `json:"meta"`
}

// Group is a SCIM group resource.
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Ref    `json:"members,omitempty"`
	Meta        Meta     `json:"meta"`
}

// ListResponse wraps a page of resources.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Resources    []any    `json:"Resources"`
}

// NewListResponse builds one, with the capitalised Resources key the
// specification requires and every client expects.
func NewListResponse(total, startIndex int, resources []any) ListResponse {
	if resources == nil {
		resources = []any{}
	}
	return ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex,
		Resources:    resources,
	}
}

// Error is SCIM's error body.
//
// Its own shape rather than Cardinal's, because a provisioning client parses
// this to decide whether to retry, to skip the record, or to stop — and one
// that cannot parse the body treats every failure the same way.
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// scimType values the specification defines for the cases that arise here.
const (
	TypeUniqueness    = "uniqueness"
	TypeInvalidValue  = "invalidValue"
	TypeInvalidPath   = "invalidPath"
	TypeMutability    = "mutability"
	TypeInvalidSyntax = "invalidSyntax"
	TypeTooMany       = "tooMany"
)

// WriteError sends a SCIM error body with the right content type.
func WriteError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Error{ //nolint:errcheck // the status is already written, so nothing can be changed
		Schemas:  []string{SchemaError},
		Status:   strconv.Itoa(status),
		SCIMType: scimType,
		Detail:   detail,
	})
}

// Write sends a resource with the right content type.
func Write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) //nolint:errcheck // as above
}

// PatchRequest is RFC 7644 §3.5.2.
type PatchRequest struct {
	Schemas    []string    `json:"schemas"`
	Operations []Operation `json:"Operations"`
}

// Operation is one change within a PATCH.
type Operation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Normalised returns the operation verb in lower case.
//
// The specification says the verb is case-insensitive, and clients differ:
// Entra sends "Add", Okta sends "add", and a provider matching one exactly
// silently ignores the other's operations — which presents as a synchronisation
// that reports success and changes nothing.
func (o Operation) Normalised() string { return strings.ToLower(strings.TrimSpace(o.Op)) }
