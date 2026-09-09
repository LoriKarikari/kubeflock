package kubeflock

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"
)

type globalOptions struct {
	ConfigPath, Kubeconfig, Kubectl, StateDir string
}

type accessCheck struct {
	Name                               string
	Verb, Group, Resource, Subresource string
	Namespaced, Advisory               bool
}

func (c accessCheck) resourceArg() string {
	if c.Group == "" {
		return c.Resource
	}
	return c.Resource + "." + c.Group
}

func (c accessCheck) qualified() string {
	name := c.resourceArg()
	if c.Subresource != "" {
		name += "/" + c.Subresource
	}
	return name
}

var requiredAccess = []accessCheck{
	{Name: "perm-get-sandboxes", Verb: "get", Group: "agents.x-k8s.io", Resource: "sandboxes", Namespaced: true},
	{Name: "perm-list-sandboxclaims", Verb: "list", Group: "extensions.agents.x-k8s.io", Resource: "sandboxclaims", Namespaced: true},
	{Name: "perm-create-sandboxclaims", Verb: "create", Group: "extensions.agents.x-k8s.io", Resource: "sandboxclaims", Namespaced: true},
	{Name: "perm-get-sandboxtemplates", Verb: "get", Group: "extensions.agents.x-k8s.io", Resource: "sandboxtemplates", Namespaced: true},
	{Name: "perm-list-sandboxwarmpools", Verb: "list", Group: "extensions.agents.x-k8s.io", Resource: "sandboxwarmpools", Namespaced: true},
	{Name: "perm-list-pods", Verb: "list", Resource: "pods", Namespaced: true},
	{Name: "perm-create-pods-exec", Verb: "create", Resource: "pods", Subresource: "exec", Namespaced: true},
	{Name: "perm-get-persistentvolumeclaims", Verb: "get", Resource: "persistentvolumeclaims", Namespaced: true},
	{Name: "perm-list-resourcequotas", Verb: "list", Resource: "resourcequotas", Namespaced: true},
	{Name: "perm-list-limitranges", Verb: "list", Resource: "limitranges", Namespaced: true},
	{Name: "perm-list-storageclasses", Verb: "list", Group: "storage.k8s.io", Resource: "storageclasses"},
	{Name: "perm-get-runtimeclasses", Verb: "get", Group: "node.k8s.io", Resource: "runtimeclasses"},
	{Name: "perm-get-namespaces", Verb: "get", Resource: "namespaces"},
}

func (a *App) runKubectl(ctx context.Context, options globalOptions, args ...string) (string, error) {
	env := []string{}
	if options.Kubeconfig != "" {
		env = append(env, "KUBECONFIG="+options.Kubeconfig)
	}
	return runCaptured(ctx, options.Kubectl, args, env, nil)
}

func baseArgs(target KubeTarget, requestTimeout string, args ...string) []string {
	return append([]string{"--context", target.Context, "--request-timeout", requestTimeout}, args...)
}

func namespacedArgs(target KubeTarget, requestTimeout string, args ...string) []string {
	return append([]string{"--context", target.Context, "-n", target.Namespace, "--request-timeout", requestTimeout}, args...)
}

func okCheck(name, message string) CheckResult {
	return CheckResult{Name: name, OK: true, Message: message}
}

func failedCheck(name, message, category string) CheckResult {
	return CheckResult{Name: name, Category: category, Message: message, Remediation: remediation(category)}
}

func commandFailure(err error, fallback string) (detail, category string) {
	var command *commandError
	if !errors.As(err, &command) {
		return truncate(sanitizeLines(err.Error()), 500), classify(err.Error(), false)
	}
	detail = cmp.Or(strings.TrimSpace(command.Stderr), strings.TrimSpace(command.Stdout), fallback)
	return truncate(sanitizeLines(detail), 500), classify(command.Stderr, command.TimedOut)
}

func (a *App) runCheck(ctx context.Context, target KubeTarget, options globalOptions, requestTimeout time.Duration) CheckReport {
	req := fmt.Sprintf("%gs", requestTimeout.Seconds())
	perCall := requestTimeout + 5*time.Second
	perCall = max(perCall, 15*time.Second)
	attempt := func(name, action string, args []string) (string, *CheckResult) {
		callCtx, cancel := context.WithTimeout(ctx, perCall)
		defer cancel()
		out, err := a.runKubectl(callCtx, options, args...)
		if err == nil {
			return out, nil
		}
		detail, category := commandFailure(err, "kubectl failed")
		result := failedCheck(name, fmt.Sprintf("could not %s: %s", action, detail), category)
		return out, &result
	}

	checks := []CheckResult{}
	versions, connectivity := attempt("api-connectivity", "reach the Kubernetes API with the saved context", baseArgs(target, req, "api-versions"))
	served := sets.New[string]()
	if connectivity != nil {
		checks = append(checks, *connectivity)
	} else {
		checks = append(checks, okCheck("api-connectivity", "API reachable with saved context"))
		served.Insert(strings.Fields(versions)...)
	}
	probe := func(name, action string, args []string, classify func(string) CheckResult) CheckResult {
		out, failure := attempt(name, action, args)
		if failure != nil {
			return *failure
		}
		return classify(out)
	}
	online := connectivity == nil
	for _, expectation := range expectedAPIGroups {
		if online && !served.Has(expectation.Group+"/v1beta1") {
			checks = append(checks, failedCheck(expectation.Check, expectation.Label+" is not served", "missing-infrastructure"))
			continue
		}
		checks = append(checks, probe(expectation.Check, "discover "+expectation.Label, baseArgs(target, req, "api-resources", "--api-group="+expectation.Group, "-o", "name"), expectation.check))
	}

	checks = append(checks,
		probe("runtimeclass-gvisor", "read RuntimeClass gvisor", baseArgs(target, req, "get", "runtimeclass", "gvisor", "-o", "json"), runtimeClassCheck),
		probe("storage", "list StorageClasses", baseArgs(target, req, "get", "storageclass", "-o", "json"), storageCheck),
		probe("namespace", fmt.Sprintf("read namespace %q", target.Namespace), baseArgs(target, req, "get", "namespace", target.Namespace, "-o", "json"), func(string) CheckResult {
			return okCheck("namespace", fmt.Sprintf("namespace %q exists", target.Namespace))
		}),
		probe("budgets-quota", "read ResourceQuotas in target namespace", namespacedArgs(target, req, "get", "resourcequota", "-o", "json"), quotaCheck),
	)
	out, failure := attempt("budgets-limits", "read LimitRanges in target namespace", namespacedArgs(target, req, "get", "limitrange", "-o", "json"))
	limits := limitsCheck(out)
	if failure != nil {
		limits = *failure
		limits.Advisory = true
	}
	checks = append(checks, limits)
	checks = append(checks, a.checkAccess(ctx, target, options, req, perCall)...)
	report := CheckReport{Context: target.Context, Namespace: target.Namespace, OK: true, Checks: checks, CheckedAt: a.now().UTC()}
	for _, check := range checks {
		if !check.OK && !check.Advisory {
			report.OK = false
		}
	}
	return report
}

var (
	computeQuotaKeys = sets.New("pods", "cpu", "memory", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory", "requests.ephemeral-storage", "limits.ephemeral-storage")
	storageQuotaKeys = sets.New("persistentvolumeclaims", "requests.storage")
)

type apiGroupExpectation struct {
	Check, Group, Label string
	Resources           []string
}

var expectedAPIGroups = []apiGroupExpectation{
	{"agents-api", "agents.x-k8s.io", "Sandbox API agents.x-k8s.io/v1beta1", []string{"sandboxes"}},
	{"extensions-api", "extensions.agents.x-k8s.io", "Sandbox extensions API extensions.agents.x-k8s.io/v1beta1", []string{"sandboxclaims", "sandboxtemplates", "sandboxwarmpools"}},
}

func (expectation apiGroupExpectation) check(out string) CheckResult {
	missing := []string{}
	lowered := strings.ToLower(out)
	for _, resource := range expectation.Resources {
		if !strings.Contains(lowered, resource) {
			missing = append(missing, resource)
		}
	}
	if len(missing) != 0 {
		return failedCheck(expectation.Check, expectation.Label+" served but missing: "+strings.Join(missing, ", "), "missing-infrastructure")
	}
	return okCheck(expectation.Check, expectation.Label+" served")
}

func runtimeClassCheck(out string) CheckResult {
	var value struct {
		Handler string `json:"handler"`
	}
	if json.Unmarshal([]byte(out), &value) != nil {
		return failedCheck("runtimeclass-gvisor", "RuntimeClass gvisor returned unreadable JSON", "unknown")
	}
	if !strings.Contains(strings.ToLower(value.Handler), "runsc") {
		return failedCheck("runtimeclass-gvisor", fmt.Sprintf("RuntimeClass gvisor handler is %q, want runsc", value.Handler), "missing-infrastructure")
	}
	return okCheck("runtimeclass-gvisor", fmt.Sprintf("RuntimeClass gvisor present (handler %s)", value.Handler))
}

func storageCheck(out string) CheckResult {
	var value struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(out), &value) != nil {
		return failedCheck("storage", "StorageClass list returned unreadable JSON", "unknown")
	}
	if len(value.Items) == 0 {
		return failedCheck("storage", "no StorageClasses available for sandbox homes", "missing-infrastructure")
	}
	names := make([]string, len(value.Items))
	defaultName := ""
	for i, item := range value.Items {
		names[i] = item.Metadata.Name
		if item.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			defaultName = item.Metadata.Name
		}
	}
	label := ""
	if defaultName != "" {
		label = " (default " + defaultName + ")"
	}
	return okCheck("storage", fmt.Sprintf("%d StorageClass(es): %s%s", len(names), strings.Join(names, ", "), label))
}

func (a *App) checkAccess(ctx context.Context, target KubeTarget, options globalOptions, req string, perCall time.Duration) []CheckResult {
	permissions := make([]CheckResult, len(requiredAccess))
	group := new(errgroup.Group)
	group.SetLimit(6)
	for i, access := range requiredAccess {
		group.Go(func() error {
			permissions[i] = a.permissionCheck(ctx, target, options, req, perCall, access)
			return nil
		})
	}
	_ = group.Wait()
	return permissions
}

func quotaCheck(raw string) CheckResult {
	var value struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Hard map[string]string `json:"hard"`
			} `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil {
		return failedCheck("budgets-quota", "ResourceQuota list returned unreadable JSON", "unknown")
	}
	if len(value.Items) == 0 {
		return failedCheck("budgets-quota", "no ResourceQuota in target namespace; set explicit compute/storage budgets via the Helm chart", "missing-infrastructure")
	}
	names := []string{}
	seen := sets.New[string]()
	for _, item := range value.Items {
		names = append(names, item.Metadata.Name)
		for key := range item.Spec.Hard {
			seen.Insert(key)
		}
	}
	hasCompute := seen.Intersection(computeQuotaKeys).Len() != 0
	hasStorage := seen.Intersection(storageQuotaKeys).Len() != 0
	if hasCompute && hasStorage {
		return okCheck("budgets-quota", "ResourceQuota present: "+strings.Join(names, ", "))
	}
	missing := []string{}
	if !hasCompute {
		missing = append(missing, "compute (pods, cpu, memory)")
	}
	if !hasStorage {
		missing = append(missing, "storage")
	}
	hard := strings.Join(slices.Sorted(maps.Keys(seen)), ", ")
	if hard == "" {
		hard = "empty"
	}
	return failedCheck("budgets-quota", fmt.Sprintf("ResourceQuota %s sets no %s budget (hard: %s)", strings.Join(names, ", "), strings.Join(missing, " and "), hard), "missing-infrastructure")
}

func limitsCheck(raw string) CheckResult {
	var value struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil {
		result := failedCheck("budgets-limits", "LimitRange list returned unreadable JSON", "unknown")
		result.Advisory = true
		return result
	}
	if len(value.Items) == 0 {
		result := failedCheck("budgets-limits", "no LimitRange in target namespace", "missing-infrastructure")
		result.Advisory = true
		return result
	}
	return okCheck("budgets-limits", fmt.Sprintf("%d LimitRange(s) present", len(value.Items)))
}

func (a *App) permissionCheck(ctx context.Context, target KubeTarget, options globalOptions, req string, timeout time.Duration, access accessCheck) CheckResult {
	shown := access.qualified()
	args := []string{"auth", "can-i", access.Verb, access.resourceArg()}
	if access.Subresource != "" {
		args = append(args, "--subresource="+access.Subresource)
	}
	if access.Namespaced {
		args = namespacedArgs(target, req, args...)
	} else {
		args = baseArgs(target, req, args...)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := a.runKubectl(callCtx, options, args...)
	var command *commandError
	if errors.As(err, &command) && strings.TrimSpace(command.Stdout) != "" {
		out = command.Stdout
	}
	answer := strings.ToLower(strings.TrimSpace(out))
	if answer == "yes" {
		return okCheck(access.Name, fmt.Sprintf("can %s %s", access.Verb, shown))
	}
	if answer == "no" || strings.HasPrefix(answer, "no ") {
		scope := "cluster scope"
		if access.Namespaced {
			scope = "namespace"
		}
		result := failedCheck(access.Name, fmt.Sprintf("cannot %s %s in %s", access.Verb, shown, scope), "denied")
		result.Advisory = access.Advisory
		return result
	}
	detail, category := commandFailure(err, sanitizeLines(out))
	result := failedCheck(access.Name, fmt.Sprintf("could not check permission %s %s: %s", access.Verb, shown, detail), category)
	result.Advisory = access.Advisory
	return result
}

func truncate(value string, size int) string {
	if len(value) <= size {
		return value
	}
	return value[:size]
}
