package scp

import (
	"context"
	"fmt"
)

// UpsertPolicy ensures a policy with the given name exists carrying exactly the
// given rules. If a policy with that exact name already exists it is updated in
// place (preserving its id); otherwise a new one is created. It returns the
// policy id and whether a new policy was created.
func (c *Client) UpsertPolicy(ctx context.Context, userID int, name, description string, rules []FirewallRule) (id int, created bool, err error) {
	existing, err := c.ListPolicies(ctx, userID, name)
	if err != nil {
		return 0, false, fmt.Errorf("listing policies: %w", err)
	}

	// q is a substring match, so filter to the exact name.
	var match *FirewallPolicy
	for i := range existing {
		if existing[i].Name == name {
			match = &existing[i]
			break
		}
	}

	save := FirewallPolicySave{Name: name, Description: description, Rules: rules}

	if match != nil {
		if err := c.UpdatePolicy(ctx, userID, match.ID, save); err != nil {
			return 0, false, fmt.Errorf("updating policy %d: %w", match.ID, err)
		}
		return match.ID, false, nil
	}

	pol, err := c.CreatePolicy(ctx, userID, save)
	if err != nil {
		return 0, false, fmt.Errorf("creating policy: %w", err)
	}
	return pol.ID, true, nil
}

// ReconcileResult describes the outcome of ReconcileInterface.
type ReconcileResult struct {
	Changed  bool            // whether a write was issued
	Task     *TaskInfo       // async task from the PUT (nil when unchanged)
	Firewall *ServerFirewall // pre-write snapshot
}

// ReconcileInterface brings an interface to the desired attachment state in a
// single write: ensure every id in ensurePresent is attached, ensure every
// policy whose name is in ensureAbsentNames is detached, and preserve all other
// user and copied policies. If the interface already matches, no write is issued
// (avoiding needless async tasks and 409 conflicts from concurrent writes).
func (c *Client) ReconcileInterface(ctx context.Context, serverID int, mac string, ensurePresent []int, ensureAbsentNames []string) (*ReconcileResult, error) {
	fw, err := c.GetFirewall(ctx, serverID, mac)
	if err != nil {
		return nil, fmt.Errorf("reading interface firewall: %w", err)
	}

	absent := make(map[string]bool, len(ensureAbsentNames))
	for _, n := range ensureAbsentNames {
		absent[n] = true
	}
	present := make(map[int]bool, len(ensurePresent))
	for _, id := range ensurePresent {
		present[id] = true
	}

	// Start from the current user policies, dropping any that must be absent.
	final := make([]int, 0, len(fw.UserPolicies)+len(ensurePresent))
	have := make(map[int]bool)
	for _, p := range fw.UserPolicies {
		if absent[p.Name] {
			continue
		}
		if !have[p.ID] {
			final = append(final, p.ID)
			have[p.ID] = true
		}
	}
	// Add any required policies not already present.
	for _, id := range ensurePresent {
		if id != 0 && !have[id] {
			final = append(final, id)
			have[id] = true
		}
	}

	// Determine whether this differs from the current set (order-independent).
	current := make(map[int]bool, len(fw.UserPolicies))
	for _, p := range fw.UserPolicies {
		current[p.ID] = true
	}
	changed := len(current) != len(final)
	if !changed {
		for _, id := range final {
			if !current[id] {
				changed = true
				break
			}
		}
	}
	if !changed {
		return &ReconcileResult{Changed: false, Firewall: fw}, nil
	}

	ids := make([]IdentifierInt, len(final))
	for i, id := range final {
		ids[i] = IdentifierInt{ID: id}
	}
	save := ServerFirewallSave{
		UserPolicies:   ids,
		CopiedPolicies: toIdentifiers(fw.CopiedPolicies),
		Active:         true,
	}
	task, err := c.SaveFirewall(ctx, serverID, mac, save)
	if err != nil {
		return nil, fmt.Errorf("saving interface firewall: %w", err)
	}
	return &ReconcileResult{Changed: true, Task: task, Firewall: fw}, nil
}

func toIdentifiers(policies []FirewallPolicy) []IdentifierInt {
	ids := make([]IdentifierInt, 0, len(policies))
	for _, p := range policies {
		ids = append(ids, IdentifierInt{ID: p.ID})
	}
	return ids
}
