package engine

import (
	"math/rand"
	"strconv"
)

// body_bind.go — nested producer/consumer body-field binding, tenant- and
// resource-type-aware (requirement #5). Extends, rather than redesigns, the
// existing binding machinery:
//
//   - Body leaves get a NEW call site into the already-tenant-scoped resource
//     graph (findCompatibleResourcesInTenant, resource_graph.go) -- today only
//     path-param substitution (pickFollowupPathValue, sequence.go) reaches it.
//   - RuntimeStore gets a new, path-qualified index alongside its existing
//     flat one, so two different nested "id" fields under different parents
//     no longer collide in the same bucket.
//
// Three-tier fallback, each tier already independently safe/tested on its
// own: path-qualified RuntimeStore -> tenant-scoped resource graph -> the
// existing flat, non-tenant-scoped dict/runtime pool
// (graphBiasedPayloadCandidates, store.go) used unmodified as the final
// fallback for every case this file doesn't have a better answer for.

type bodyBindCtx struct {
	f         *Fuzzer
	tenantKey string
}

// newBodyBindCtx derives binding context from the active sequence chain, if
// any. tenantKey stays "" for a non-chained render (matches
// pickFollowupPathValue's/store.go's own documented behavior for
// SequenceState-less calls: tenant scoping only applies once a chain has
// resolved one).
func (f *Fuzzer) newBodyBindCtx(ctx *WorkItem) *bodyBindCtx {
	tk := ""
	if ctx != nil && ctx.SeqState != nil {
		tk = ctx.SeqState.TenantKey
	}
	return &bodyBindCtx{f: f, tenantKey: tk}
}

// bindLeaf resolves a concrete value for an id-shaped scalar leaf. Only
// called for nodes with a non-empty PayloadKey (schema_ast.py already decided
// this field is id-shaped/dictionary-worthy -- same signal Segment.PayloadKey
// already carries for the legacy flat path); returns ok=false for anything
// else, or when no tier has a real bound value, so the caller falls through
// to defaultLeafValue's pure schema-derived synthesis.
func (b *bodyBindCtx) bindLeaf(node *BodyNode) (value string, label string, ok bool) {
	if b == nil || b.f == nil || b.f.runtime == nil || node == nil || node.PayloadKey == "" {
		return "", "", false
	}
	key := node.PayloadKey

	// Tier 1: path-qualified RuntimeStore -- the most specific match, keyed by
	// exactly this schema position (resource type + dotted path), not just a
	// same-named field anywhere in the response history.
	if rt := resourceTypeFromKeyName(key); rt != "" && node.Path != "" {
		if vals := b.f.runtime.getPathValues(rt + "." + node.Path); len(vals) > 0 {
			return vals[rand.Intn(len(vals))], "bodypath_" + rt, true
		}
	}

	// Tier 2: tenant-scoped resource graph -- correct type, correct tenant,
	// just not necessarily the exact same nested position before.
	if b.tenantKey != "" && b.f.cfg.ResourceGraphEnabled {
		if rt := resourceTypeFromKeyName(key); rt != "" {
			if insts := b.f.resourceGraph.findCompatibleResourcesInTenant(rt, b.tenantKey,
				LifecycleCreated, LifecycleReadable, LifecycleModified); len(insts) > 0 {
				return insts[rand.Intn(len(insts))].Canonical.RawValue, "bodytenant_" + rt, true
			}
		}
	}

	// Tier 3: the existing flat, non-tenant-scoped pool -- unmodified,
	// same one the legacy custom_payload render path already uses.
	if cands := b.f.graphBiasedPayloadCandidates(key); len(cands) > 0 {
		return cands[rand.Intn(len(cands))], "dict_" + key, true
	}

	return "", "", false
}

// bodyLeafValueForBind adapts bindLeaf into the bodyLeafValueFunc shape
// buildBodyValue expects, falling back to defaultLeafValue for anything
// bindLeaf declines (non-id-shaped fields, or an id-shaped field with no
// bound value available in any tier).
func bodyLeafValueForBind(bind *bodyBindCtx) bodyLeafValueFunc {
	return func(node *BodyNode) (string, BodyValueKind) {
		if v, _, ok := bind.bindLeaf(node); ok {
			switch node.ScalarType {
			case "integer", "number":
				// Bound values come from runtime-observed IDs and resource-graph
				// identities, which are frequently non-numeric strings (e.g.
				// "REF-9581") even when the schema declares an integer field --
				// BVNumber's serializer writes its Str verbatim, unquoted, so
				// handing it a non-numeric value here would emit broken JSON
				// (`"authorUserId":REF-9581`). Fall back to BVString, which quotes
				// it -- a real type-mismatch value on the wire is a legitimate,
				// safer outcome than corrupting the request.
				if _, err := strconv.ParseFloat(v, 64); err == nil {
					return v, BVNumber
				}
				return v, BVString
			case "boolean":
				return v, BVBool
			default:
				return v, BVString
			}
		}
		return defaultLeafValue(node)
	}
}
