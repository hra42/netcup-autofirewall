// Package scp contains the typed data model and HTTP client for NetCup's
// Server Control Panel (SCP) API.
package scp

// Firewall rule enum values.
const (
	DirectionIngress = "INGRESS"
	DirectionEgress  = "EGRESS"

	ProtocolTCP    = "TCP"
	ProtocolUDP    = "UDP"
	ProtocolICMP   = "ICMP"
	ProtocolICMPv6 = "ICMPv6"

	ActionAccept = "ACCEPT"
	ActionDrop   = "DROP"

	ImplicitAcceptAll = "ACCEPT_ALL"
	ImplicitDropAll   = "DROP_ALL"
)

// FirewallRule is a single firewall rule. Ports are single strings ("22" or a
// range "1024-65535"); empty sources/destinations mean "any".
type FirewallRule struct {
	Direction        string   `json:"direction"`
	Protocol         string   `json:"protocol"`
	Action           string   `json:"action"`
	Description      string   `json:"description,omitempty"`
	Sources          []string `json:"sources,omitempty"`
	Destinations     []string `json:"destinations,omitempty"`
	SourcePorts      string   `json:"sourcePorts,omitempty"`
	DestinationPorts string   `json:"destinationPorts,omitempty"`
}

// FirewallPolicySave is the request body for creating/updating a policy.
type FirewallPolicySave struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Rules       []FirewallRule `json:"rules"`
}

// FirewallPolicy is the server representation of a policy (adds id).
type FirewallPolicy struct {
	ID          int            `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Rules       []FirewallRule `json:"rules"`
}

// IdentifierInt references an entity by numeric id ({"id": N}).
type IdentifierInt struct {
	ID int `json:"id"`
}

// ServerFirewall is the read-side (GET) representation of an interface firewall.
// userPolicies/copiedPolicies are full policy objects here.
type ServerFirewall struct {
	CopiedPolicies      []FirewallPolicy `json:"copiedPolicies"`
	UserPolicies        []FirewallPolicy `json:"userPolicies"`
	IngressImplicitRule string           `json:"ingressImplicitRule"`
	EgressImplicitRule  string           `json:"egressImplicitRule"`
	Consistent          bool             `json:"consistent"`
	Active              bool             `json:"active"`
}

// ServerFirewallSave is the write-side (PUT) body; policies are referenced by id.
type ServerFirewallSave struct {
	CopiedPolicies []IdentifierInt `json:"copiedPolicies"`
	UserPolicies   []IdentifierInt `json:"userPolicies"`
	Active         bool            `json:"active"`
}

// TaskInfo is the async task descriptor returned by 202 responses.
type TaskInfo struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Message string `json:"message"`
}

// UserInfo is the subset of the Keycloak userinfo response we need. The SCP user
// id is returned as a string of digits, distinct from the CCP customer number in
// preferred_username.
type UserInfo struct {
	ID string `json:"id"`
}
