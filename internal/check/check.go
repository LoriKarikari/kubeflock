// Package check implements the read-only cluster prerequisite check for
// issue #1. Every Kubernetes interaction goes through kubectl with an
// explicit --context and --request-timeout and uses only read verbs
// (api-versions, api-resources, get, auth can-i). The check never creates,
// patches, or deletes cluster state; permission probing uses the ephemeral
// SelfSubjectAccessReview behind `kubectl auth can-i`, which persists nothing.
package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LoriKarikari/kubeflock/internal/config"
	"github.com/LoriKarikari/kubeflock/internal/kubectl"
)

// Options tunes the check without changing its read-only contract.
type Options struct {
	Runner         kubectl.Runner
	RequestTimeout time.Duration
	// Now is injected for stable test output.
	Now func() time.Time
}

func (o Options) requestTimeoutSeconds() string {
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 10 * time.Second
	}
	return fmt.Sprintf("%.0fs", o.RequestTimeout.Seconds())
}

// Result is one prerequisite outcome.
type Result struct {
	Name        string `json:"name"`
	OK          bool   `json:"ok"`
	Advisory    bool   `json:"advisory,omitempty"`
	Category    string `json:"category,omitempty"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// Report is the whole check outcome for CLI and Herdr consumption.
type Report struct {
	Context   string   `json:"context"`
	Namespace string   `json:"namespace"`
	OK        bool     `json:"ok"`
	Checks    []Result `json:"checks"`
	CheckedAt string   `json:"checkedAt"`
}

func ok(name, msg string) Result { return Result{Name: name, OK: true, Message: msg} }

func fail(name, msg string, cat Category) Result {
	return Result{Name: name, Message: msg, Category: string(cat), Remediation: Remediation(cat)}
}

func advisory(name, msg string, cat Category) Result {
	r := fail(name, msg, cat)
	r.Advisory = true
	return r
}

// requiredPerm describes one RBAC probe. Namespaced perms run with -n,
// cluster-scoped perms run without it.
type requiredPerm struct {
	Verb       string
	Resource   string
	Namespaced bool
	Advisory   bool
}

var requiredPerms = []requiredPerm{
	{"get", "sandboxes.agents.x-k8s.io", true, false},
	{"list", "sandboxes.agents.x-k8s.io", true, false},
	{"watch", "sandboxes.agents.x-k8s.io", true, false},
	{"create", "sandboxes.agents.x-k8s.io", true, false},
	{"patch", "sandboxes.agents.x-k8s.io", true, false},
	{"delete", "sandboxes.agents.x-k8s.io", true, false},
	{"get", "sandboxclaims.extensions.agents.x-k8s.io", true, false},
	{"list", "sandboxclaims.extensions.agents.x-k8s.io", true, false},
	{"create", "sandboxclaims.extensions.agents.x-k8s.io", true, false},
	{"patch", "sandboxclaims.extensions.agents.x-k8s.io", true, false},
	{"delete", "sandboxclaims.extensions.agents.x-k8s.io", true, false},
	{"get", "sandboxtemplates.extensions.agents.x-k8s.io", true, false},
	{"list", "sandboxtemplates.extensions.agents.x-k8s.io", true, false},
	{"get", "sandboxwarmpools.extensions.agents.x-k8s.io", true, false},
	{"list", "sandboxwarmpools.extensions.agents.x-k8s.io", true, false},
	{"get", "pods", true, false},
	{"list", "pods", true, false},
	{"create", "pods/exec", true, false},
	{"get", "pods/log", true, false},
	{"get", "persistentvolumeclaims", true, false},
	{"list", "persistentvolumeclaims", true, false},
	{"get", "resourcequotas", true, false},
	{"list", "resourcequotas", true, false},
	{"get", "limitranges", true, false},
	{"get", "secrets", true, true},
	{"get", "storageclasses.storage.k8s.io", false, false},
	{"list", "storageclasses.storage.k8s.io", false, false},
	{"get", "runtimeclasses.node.k8s.io", false, false},
	{"get", "namespaces", false, false},
}

// Run executes every prerequisite check. It performs no cluster writes.
func Run(ctx context.Context, cfg config.Config, opt Options) Report {
	now := time.Now().UTC()
	if opt.Now != nil {
		now = opt.Now()
	}
	rep := Report{
		Context:   cfg.Context,
		Namespace: cfg.Namespace,
		CheckedAt: now.Format(time.RFC3339),
	}
	add := func(r Result) { rep.Checks = append(rep.Checks, r) }

	// 1. API reachability + auth. This doubles as the connectivity probe.
	if out, err := opt.Runner.Run(ctx, baseArgs(cfg, opt, "api-versions")...); err != nil {
		add(classifiedResult("api-connectivity", "reach the Kubernetes API with the saved context", out, err))
	} else if !strings.Contains(out, "agents.x-k8s.io") {
		// Reachable but Agent Sandbox API groups absent from discovery.
		add(ok("api-connectivity", "API reachable with saved context"))
	} else {
		add(ok("api-connectivity", "API reachable with saved context"))
	}

	// 2. Served Agent Sandbox APIs via discovery (read-only).
	checkAPIResources(ctx, cfg, opt, &rep)

	// 3. gVisor RuntimeClass.
	checkRuntimeClass(ctx, cfg, opt, &rep)

	// 4. Storage classes.
	checkStorage(ctx, cfg, opt, &rep)

	// 5. Namespace, quotas, limits.
	checkNamespaceBudgets(ctx, cfg, opt, &rep)

	// 6. Permissions (concurrent, still read-only).
	checkPermissions(ctx, cfg, opt, &rep)

	rep.OK = true
	for _, c := range rep.Checks {
		if !c.OK && !c.Advisory {
			rep.OK = false
			break
		}
	}
	_ = add // keep linter quiet if reordered
	return rep
}

func baseArgs(cfg config.Config, opt Options, args ...string) []string {
	base := []string{"--context", cfg.Context, "--request-timeout", opt.requestTimeoutSeconds()}
	return append(base, args...)
}

func namespacedArgs(cfg config.Config, opt Options, args ...string) []string {
	base := []string{"--context", cfg.Context, "-n", cfg.Namespace, "--request-timeout", opt.requestTimeoutSeconds()}
	return append(base, args...)
}

func classifiedResult(name, action string, stdout string, err error) Result {
	var ke *kubectl.Error
	stderr := ""
	timedOut := kubectl.TimeoutError(err)
	if e, ok := err.(*kubectl.Error); ok {
		ke = e
		stderr = e.Stderr
		_ = ke
	}
	cat := Classify(stderr, timedOut)
	msg := fmt.Sprintf("could not %s: %s", action, SanitizeLines(firstNonEmpty(stderr, stdout, err.Error())))
	return fail(name, msg, cat)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			// Keep output short for CLI/Herdr display.
			s = strings.TrimSpace(s)
			if len(s) > 500 {
				s = s[:500]
			}
			return s
		}
	}
	return "unknown error"
}

func checkAPIResources(ctx context.Context, cfg config.Config, opt Options, rep *Report) {
	type apiCheck struct {
		name    string
		group   string
		want    []string
		display string
	}
	checks := []apiCheck{
		{"agents-api", "agents.x-k8s.io", []string{"sandboxes"}, "Sandbox API agents.x-k8s.io/v1beta1"},
		{"extensions-api", "extensions.agents.x-k8s.io", []string{"sandboxclaims", "sandboxtemplates", "sandboxwarmpools"}, "Sandbox extensions API extensions.agents.x-k8s.io/v1beta1"},
	}
	for _, c := range checks {
		out, err := opt.Runner.Run(ctx, baseArgs(cfg, opt, "api-resources", "--api-group="+c.group, "-o", "name")...)
		if err != nil {
			rep.Checks = append(rep.Checks, classifiedResult(c.name, "discover "+c.display, out, err))
			continue
		}
		missing := []string{}
		low := strings.ToLower(out)
		for _, w := range c.want {
			if !strings.Contains(low, w) {
				missing = append(missing, w)
			}
		}
		if len(missing) > 0 {
			rep.Checks = append(rep.Checks, fail(c.name,
				fmt.Sprintf("%s served but missing: %s", c.display, strings.Join(missing, ", ")),
				CategoryMissing))
			continue
		}
		rep.Checks = append(rep.Checks, ok(c.name, c.display+" served"))
	}
}

func checkRuntimeClass(ctx context.Context, cfg config.Config, opt Options, rep *Report) {
	const name = "runtimeclass-gvisor"
	out, err := opt.Runner.Run(ctx, baseArgs(cfg, opt, "get", "runtimeclass", "gvisor", "-o", "json")...)
	if err != nil {
		rep.Checks = append(rep.Checks, classifiedResult(name, "read RuntimeClass gvisor", out, err))
		return
	}
	var rc struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Handler string `json:"handler"`
	}
	if err := json.Unmarshal([]byte(out), &rc); err != nil {
		rep.Checks = append(rep.Checks, fail(name, "RuntimeClass gvisor returned unreadable JSON", CategoryUnknown))
		return
	}
	if !strings.Contains(strings.ToLower(rc.Handler), "runsc") {
		rep.Checks = append(rep.Checks, fail(name,
			fmt.Sprintf("RuntimeClass gvisor handler is %q, want runsc", rc.Handler),
			CategoryMissing))
		return
	}
	rep.Checks = append(rep.Checks, ok(name, fmt.Sprintf("RuntimeClass gvisor present (handler %s)", rc.Handler)))
}

func checkStorage(ctx context.Context, cfg config.Config, opt Options, rep *Report) {
	const name = "storage"
	out, err := opt.Runner.Run(ctx, baseArgs(cfg, opt, "get", "storageclass", "-o", "json")...)
	if err != nil {
		rep.Checks = append(rep.Checks, classifiedResult(name, "list StorageClasses", out, err))
		return
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Provisioner string `json:"provisioner"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		rep.Checks = append(rep.Checks, fail(name, "StorageClass list returned unreadable JSON", CategoryUnknown))
		return
	}
	if len(list.Items) == 0 {
		rep.Checks = append(rep.Checks, fail(name, "no StorageClasses available for sandbox homes", CategoryMissing))
		return
	}
	names := []string{}
	def := ""
	for _, sc := range list.Items {
		names = append(names, sc.Metadata.Name)
		if sc.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			def = sc.Metadata.Name
		}
	}
	msg := fmt.Sprintf("%d StorageClass(es): %s", len(names), strings.Join(names, ", "))
	if def != "" {
		msg += fmt.Sprintf(" (default %s)", def)
	}
	rep.Checks = append(rep.Checks, ok(name, msg))
}

func checkNamespaceBudgets(ctx context.Context, cfg config.Config, opt Options, rep *Report) {
	// Namespace existence.
	if out, err := opt.Runner.Run(ctx, baseArgs(cfg, opt, "get", "namespace", cfg.Namespace, "-o", "json")...); err != nil {
		rep.Checks = append(rep.Checks, classifiedResult("namespace", fmt.Sprintf("read namespace %q", cfg.Namespace), out, err))
	} else {
		rep.Checks = append(rep.Checks, ok("namespace", fmt.Sprintf("namespace %q exists", cfg.Namespace)))
	}

	// ResourceQuotas (budgets). Missing quotas fail: setup requires explicit budgets.
	if out, err := opt.Runner.Run(ctx, namespacedArgs(cfg, opt, "get", "resourcequota", "-o", "json")...); err != nil {
		rep.Checks = append(rep.Checks, classifiedResult("budgets-quota", "read ResourceQuotas in target namespace", out, err))
	} else {
		var q struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &q); err != nil {
			rep.Checks = append(rep.Checks, fail("budgets-quota", "ResourceQuota list returned unreadable JSON", CategoryUnknown))
		} else if len(q.Items) == 0 {
			rep.Checks = append(rep.Checks, fail("budgets-quota", "no ResourceQuota in target namespace; set explicit compute/storage budgets via the Helm chart", CategoryMissing))
		} else {
			names := []string{}
			for _, i := range q.Items {
				names = append(names, i.Metadata.Name)
			}
			rep.Checks = append(rep.Checks, ok("budgets-quota", fmt.Sprintf("ResourceQuota present: %s", strings.Join(names, ", "))))
		}
	}

	// LimitRanges are advisory: useful but not a hard gate for the check.
	if out, err := opt.Runner.Run(ctx, namespacedArgs(cfg, opt, "get", "limitrange", "-o", "json")...); err != nil {
		r := classifiedResult("budgets-limits", "read LimitRanges in target namespace", out, err)
		r.Advisory = true
		r.Name = "budgets-limits"
		rep.Checks = append(rep.Checks, r)
	} else {
		var l struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal([]byte(out), &l); err != nil {
			r := fail("budgets-limits", "LimitRange list returned unreadable JSON", CategoryUnknown)
			r.Advisory = true
			rep.Checks = append(rep.Checks, r)
		} else if len(l.Items) == 0 {
			rep.Checks = append(rep.Checks, advisory("budgets-limits", "no LimitRange in target namespace", CategoryMissing))
		} else {
			rep.Checks = append(rep.Checks, ok("budgets-limits", fmt.Sprintf("%d LimitRange(s) present", len(l.Items))))
		}
	}
}

func checkPermissions(ctx context.Context, cfg config.Config, opt Options, rep *Report) {
	type permOutcome struct {
		idx int
		res Result
	}
	outcomes := make([]Result, len(requiredPerms))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, p := range requiredPerms {
		i, p := i, p
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				outcomes[i] = fail("perm-"+p.Verb+"-"+p.Resource, "permission check cancelled: "+ctx.Err().Error(), CategoryTimeout)
				return
			}
			args := baseArgs(cfg, opt, "auth", "can-i", p.Verb, p.Resource)
			if p.Namespaced {
				// Insert -n before request-timeout? Order is free; rebuild correctly.
				args = namespacedArgs(cfg, opt, "auth", "can-i", p.Verb, p.Resource)
			}
			out, err := opt.Runner.Run(ctx, args...)
			name := "perm-" + p.Verb + "-" + shortResource(p.Resource)
			answer := strings.TrimSpace(strings.ToLower(out))
			if err == nil && strings.Contains(answer, "yes") {
				outcomes[i] = ok(name, fmt.Sprintf("can %s %s", p.Verb, p.Resource))
				return
			}
			if strings.Contains(answer, "no") {
				msg := fmt.Sprintf("cannot %s %s in %s", p.Verb, p.Resource, scope(p))
				r := fail(name, msg, CategoryDenied)
				if p.Advisory {
					r.Advisory = true
				}
				outcomes[i] = r
				return
			}
			if err != nil {
				r := classifiedResult(name, fmt.Sprintf("check permission %s %s", p.Verb, p.Resource), out, err)
				if p.Advisory {
					r.Advisory = true
				}
				outcomes[i] = r
				return
			}
			r := fail(name, fmt.Sprintf("unexpected permission answer for %s %s: %q", p.Verb, p.Resource, SanitizeLines(out)), CategoryUnknown)
			if p.Advisory {
				r.Advisory = true
			}
			outcomes[i] = r
		}()
	}
	wg.Wait()
	rep.Checks = append(rep.Checks, outcomes...)
}

func shortResource(r string) string {
	r = strings.ReplaceAll(r, ".agents.x-k8s.io", "")
	r = strings.ReplaceAll(r, ".extensions", "")
	r = strings.ReplaceAll(r, ".storage.k8s.io", "")
	r = strings.ReplaceAll(r, ".node.k8s.io", "")
	r = strings.ReplaceAll(r, "/", "-")
	return r
}

func scope(p requiredPerm) string {
	if p.Namespaced {
		return "namespace"
	}
	return "cluster scope"
}
