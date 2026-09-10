package kubeflock

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	extensionsAPIGroup    = "extensions.agents.x-k8s.io"
	runtimeClassCheckName = "runtimeclass-gvisor"
	quotaCheckName        = "budgets-quota"
	limitsCheckName       = "budgets-limits"
)

type globalOptions struct {
	ConfigPath string
	Kubeconfig string
	Kubectl    string
	StateDir   string
}

type accessCheck struct {
	Name        string
	Verb        string
	Group       string
	Resource    string
	Subresource string
	Namespaced  bool
	Advisory    bool
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
	{Name: "perm-patch-sandboxes", Verb: "patch", Group: "agents.x-k8s.io", Resource: "sandboxes", Namespaced: true},
	{Name: "perm-delete-sandboxes", Verb: "delete", Group: "agents.x-k8s.io", Resource: "sandboxes", Namespaced: true},
	{Name: "perm-list-sandboxclaims", Verb: "list", Group: extensionsAPIGroup, Resource: "sandboxclaims", Namespaced: true},
	{Name: "perm-create-sandboxclaims", Verb: "create", Group: extensionsAPIGroup, Resource: "sandboxclaims", Namespaced: true},
	{Name: "perm-delete-sandboxclaims", Verb: "delete", Group: extensionsAPIGroup, Resource: "sandboxclaims", Namespaced: true},
	{Name: "perm-get-sandboxtemplates", Verb: "get", Group: extensionsAPIGroup, Resource: "sandboxtemplates", Namespaced: true},
	{Name: "perm-list-sandboxwarmpools", Verb: "list", Group: extensionsAPIGroup, Resource: "sandboxwarmpools", Namespaced: true},
	{Name: "perm-list-pods", Verb: "list", Resource: "pods", Namespaced: true},
	{Name: "perm-create-pods-exec", Verb: "create", Resource: "pods", Subresource: "exec", Namespaced: true},
	{Name: "perm-get-persistentvolumeclaims", Verb: "get", Resource: "persistentvolumeclaims", Namespaced: true},
	{Name: "perm-patch-persistentvolumeclaims", Verb: "patch", Resource: "persistentvolumeclaims", Namespaced: true},
	{Name: "perm-list-resourcequotas", Verb: "list", Resource: "resourcequotas", Namespaced: true},
	{Name: "perm-list-limitranges", Verb: "list", Resource: "limitranges", Namespaced: true},
	{Name: "perm-list-storageclasses", Verb: "list", Group: "storage.k8s.io", Resource: "storageclasses"},
	{Name: "perm-get-runtimeclasses", Verb: "get", Group: "node.k8s.io", Resource: "runtimeclasses"},
	{Name: "perm-get-namespaces", Verb: "get", Resource: "namespaces"},
}

func runKubectl(ctx context.Context, options globalOptions, args ...string) (string, error) {
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

func failedCheck(name, message string) CheckResult {
	return CheckResult{Name: name, Message: message}
}

func (a *App) runCheck(ctx context.Context, target KubeTarget, options globalOptions, requestTimeout time.Duration) CheckReport {
	requestTimeoutArg := requestTimeout.String()
	perCall := requestTimeout + 5*time.Second
	perCall = max(perCall, 15*time.Second)
	attempt := func(name, action string, args []string) (string, *CheckResult) {
		callCtx, cancel := context.WithTimeout(ctx, perCall)
		defer cancel()
		out, err := runKubectl(callCtx, options, args...)
		if err == nil {
			return out, nil
		}
		result := failedCheck(name, "could not "+action)
		return out, &result
	}

	checks := []CheckResult{}
	versions, connectivity := attempt(
		"api-connectivity",
		"reach the Kubernetes API with the saved context",
		baseArgs(target, requestTimeoutArg, "api-versions"),
	)
	served := sets.New[string]()
	if connectivity != nil {
		checks = append(checks, *connectivity)
	} else {
		checks = append(checks, okCheck("api-connectivity", "API reachable with saved context"))
		served.Insert(strings.Fields(versions)...)
	}
	probe := func(name, action string, args []string, checkOutput func(string) CheckResult) CheckResult {
		out, failure := attempt(name, action, args)
		if failure != nil {
			return *failure
		}
		return checkOutput(out)
	}
	online := connectivity == nil
	for _, expectation := range expectedAPIGroups {
		if online && !served.Has(expectation.Group+"/v1beta1") {
			checks = append(checks, failedCheck(expectation.Check, expectation.Label+" is not served"))
			continue
		}
		checks = append(checks, probe(
			expectation.Check,
			"discover "+expectation.Label,
			baseArgs(target, requestTimeoutArg, "api-resources", "--api-group="+expectation.Group, "-o", "name"),
			expectation.check,
		))
	}

	checks = append(checks,
		probe(runtimeClassCheckName, "read RuntimeClass gvisor", baseArgs(target, requestTimeoutArg, "get", "runtimeclass", "gvisor", "-o", "json"), runtimeClassCheck),
		probe("storage", "list StorageClasses", baseArgs(target, requestTimeoutArg, "get", "storageclass", "-o", "json"), storageCheck),
		probe("namespace", fmt.Sprintf("read namespace %q", target.Namespace), baseArgs(target, requestTimeoutArg, "get", "namespace", target.Namespace, "-o", "json"), func(string) CheckResult {
			return okCheck("namespace", fmt.Sprintf("namespace %q exists", target.Namespace))
		}),
		probe(quotaCheckName, "read ResourceQuotas in target namespace", namespacedArgs(target, requestTimeoutArg, "get", "resourcequota", "-o", "json"), quotaCheck),
	)
	out, failure := attempt(limitsCheckName, "read LimitRanges in target namespace", namespacedArgs(target, requestTimeoutArg, "get", "limitrange", "-o", "json"))
	limits := limitsCheck(out)
	if failure != nil {
		limits = *failure
		limits.Advisory = true
	}
	checks = append(checks, limits)
	checks = append(checks, checkAccess(ctx, target, options, requestTimeoutArg, perCall)...)
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
	Check     string
	Group     string
	Label     string
	Resources []string
}

var expectedAPIGroups = []apiGroupExpectation{
	{
		Check:     "agents-api",
		Group:     "agents.x-k8s.io",
		Label:     "Sandbox API agents.x-k8s.io/v1beta1",
		Resources: []string{"sandboxes"},
	},
	{
		Check: "extensions-api",
		Group: extensionsAPIGroup,
		Label: "Sandbox extensions API extensions.agents.x-k8s.io/v1beta1",
		Resources: []string{
			"sandboxclaims",
			"sandboxtemplates",
			"sandboxwarmpools",
		},
	},
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
		return failedCheck(expectation.Check, expectation.Label+" served but missing: "+strings.Join(missing, ", "))
	}
	return okCheck(expectation.Check, expectation.Label+" served")
}

func runtimeClassCheck(out string) CheckResult {
	var value struct {
		Handler string `json:"handler"`
	}
	if json.Unmarshal([]byte(out), &value) != nil {
		return failedCheck(runtimeClassCheckName, "RuntimeClass gvisor returned unreadable JSON")
	}
	if !strings.Contains(strings.ToLower(value.Handler), "runsc") {
		return failedCheck(runtimeClassCheckName, fmt.Sprintf("RuntimeClass gvisor handler is %q, want runsc", value.Handler))
	}
	return okCheck(runtimeClassCheckName, fmt.Sprintf("RuntimeClass gvisor present (handler %s)", value.Handler))
}

type storageClass struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

func storageCheck(out string) CheckResult {
	var value struct {
		Items []storageClass `json:"items"`
	}
	if json.Unmarshal([]byte(out), &value) != nil {
		return failedCheck("storage", "StorageClass list returned unreadable JSON")
	}
	if len(value.Items) == 0 {
		return failedCheck("storage", "no StorageClasses available for sandbox homes")
	}
	names := make([]string, len(value.Items))
	label := ""
	for i, item := range value.Items {
		names[i] = item.Metadata.Name
		if label == "" && item.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			label = " (default " + item.Metadata.Name + ")"
		}
	}
	return okCheck("storage", fmt.Sprintf("%d StorageClass(es): %s%s", len(names), strings.Join(names, ", "), label))
}

func checkAccess(ctx context.Context, target KubeTarget, options globalOptions, req string, perCall time.Duration) []CheckResult {
	permissions := make([]CheckResult, len(requiredAccess))
	group := new(errgroup.Group)
	group.SetLimit(6)
	for i, access := range requiredAccess {
		group.Go(func() error {
			permissions[i] = permissionCheck(ctx, target, options, req, perCall, access)
			return nil
		})
	}
	_ = group.Wait()
	return permissions
}

type resourceQuota struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Hard map[string]string `json:"hard"`
	} `json:"spec"`
}

func quotaCheck(raw string) CheckResult {
	var value struct {
		Items []resourceQuota `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil {
		return failedCheck(quotaCheckName, "ResourceQuota list returned unreadable JSON")
	}
	if len(value.Items) == 0 {
		return failedCheck(quotaCheckName, "no ResourceQuota in target namespace; set explicit compute/storage budgets via the Helm chart")
	}
	names := make([]string, len(value.Items))
	seen := sets.New[string]()
	for i, item := range value.Items {
		names[i] = item.Metadata.Name
		for key := range item.Spec.Hard {
			seen.Insert(key)
		}
	}
	hasCompute := seen.Intersection(computeQuotaKeys).Len() != 0
	hasStorage := seen.Intersection(storageQuotaKeys).Len() != 0
	if hasCompute && hasStorage {
		return okCheck(quotaCheckName, "ResourceQuota present: "+strings.Join(names, ", "))
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
	return failedCheck(quotaCheckName, fmt.Sprintf("ResourceQuota %s sets no %s budget (hard: %s)", strings.Join(names, ", "), strings.Join(missing, " and "), hard))
}

func limitsCheck(raw string) CheckResult {
	var value struct {
		Items []jsontext.Value `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil {
		result := failedCheck(limitsCheckName, "LimitRange list returned unreadable JSON")
		result.Advisory = true
		return result
	}
	if len(value.Items) == 0 {
		result := failedCheck(limitsCheckName, "no LimitRange in target namespace")
		result.Advisory = true
		return result
	}
	return okCheck(limitsCheckName, fmt.Sprintf("%d LimitRange(s) present", len(value.Items)))
}

func permissionCheck(
	ctx context.Context,
	target KubeTarget,
	options globalOptions,
	requestTimeout string,
	timeout time.Duration,
	access accessCheck,
) CheckResult {
	shown := access.qualified()
	args := []string{"auth", "can-i", access.Verb, access.resourceArg()}
	if access.Subresource != "" {
		args = append(args, "--subresource="+access.Subresource)
	}
	if access.Namespaced {
		args = namespacedArgs(target, requestTimeout, args...)
	} else {
		args = baseArgs(target, requestTimeout, args...)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := runKubectl(callCtx, options, args...)
	if command, ok := errors.AsType[*commandError](err); ok && strings.TrimSpace(command.Stdout) != "" {
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
		result := failedCheck(access.Name, fmt.Sprintf("cannot %s %s in %s", access.Verb, shown, scope))
		result.Advisory = access.Advisory
		return result
	}
	message := fmt.Sprintf("could not check permission %s %s", access.Verb, shown)
	if err == nil {
		message += ": kubectl returned an unexpected response"
	}
	result := failedCheck(access.Name, message)
	result.Advisory = access.Advisory
	return result
}
