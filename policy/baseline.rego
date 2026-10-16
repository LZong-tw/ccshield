# ccshield default policy for the personal-subscription lane.
#
# Only two findings inputs vary at runtime: secretFindings (Gitleaks) and
# piiFindings (the Privacy worker). repositoryClass, pathClasses and
# interactive are pinned by defaultShieldLauncherContext() in
# src/shield/service.mjs, so a rule keyed on repositoryClass == "internal"
# would never fire. The restricted-* rules below are kept because they are
# correct, not because they are reachable from `shield launch` today.
#
# Rule bodies are mutually exclusive on purpose: two simultaneously true
# bodies producing different values is a Rego conflict, which surfaces as
# "shield policy evaluation failed" and a 503 on every request.
package ccshield.shield

default decision := {
	"action": "allow",
	"reasonCodes": [],
	"approvalEligible": false,
	"redactions": [],
}

decision := {
	"action": "block",
	"reasonCodes": ["confirmed-secret"],
	"approvalEligible": false,
	"redactions": [],
} if {
	count(input.secretFindings) > 0
}

decision := {
	"action": "block",
	"reasonCodes": ["restricted-data"],
	"approvalEligible": false,
	"redactions": [],
} if {
	count(input.secretFindings) == 0
	restricted
}

# Native Privacy findings are sent only after the worker supplies a verified
# byte-for-byte redacted replacement, including OPF-only secret findings.
# Gitleaks findings and restricted classifications still block above.
decision := {
	"action": "redact",
	"reasonCodes": ["subscription-pii"],
	"approvalEligible": false,
	"redactions": [],
} if {
	count(input.secretFindings) == 0
	not restricted
	input.destinationClass == "subscription"
	count(input.piiFindings) > 0
}

restricted if input.repositoryClass == "restricted"

restricted if {
	some pathClass in input.pathClasses
	restricted_path_class(pathClass)
}

restricted_path_class("environment")

restricted_path_class("terraform_state")

restricted_path_class("credential_store")

restricted_path_class("production_config")
