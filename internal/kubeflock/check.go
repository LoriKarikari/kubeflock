package kubeflock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

type globalOptions struct {
	ConfigPath, Kubeconfig, Kubectl, StateDir string
}

type permission struct {
	Verb, Resource, Subresource string
	Namespaced, Advisory        bool
}

var requiredPermissions = []permission{
	{Verb: "get", Resource: "sandboxes.agents.x-k8s.io", Namespaced: true},
	{Verb: "list", Resource: "sandboxclaims.extensions.agents.x-k8s.io", Namespaced: true},
	{Verb: "create", Resource: "sandboxclaims.extensions.agents.x-k8s.io", Namespaced: true},
	{Verb: "get", Resource: "sandboxtemplates.extensions.agents.x-k8s.io", Namespaced: true},
	{Verb: "list", Resource: "sandboxwarmpools.extensions.agents.x-k8s.io", Namespaced: true},
	{Verb: "list", Resource: "pods", Namespaced: true},
	{Verb: "create", Resource: "pods", Subresource: "exec", Namespaced: true},
	{Verb: "get", Resource: "persistentvolumeclaims", Namespaced: true},
	{Verb: "list", Resource: "resourcequotas", Namespaced: true},
	{Verb: "list", Resource: "limitranges", Namespaced: true},
	{Verb: "list", Resource: "storageclasses.storage.k8s.io"},
	{Verb: "get", Resource: "runtimeclasses.node.k8s.io"},
	{Verb: "get", Resource: "namespaces"},
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

func commandOutput(err error) (stderr, stdout string, timedOut bool) {
	var command *commandError
	if errors.As(err, &command) {
		return command.Stderr, command.Stdout, command.Kind == "timeout"
	}
	return err.Error(), "", false
}

func (a *App) runCheck(ctx context.Context, target KubeTarget, options globalOptions, requestTimeout time.Duration) CheckReport {
	req := fmt.Sprintf("%gs", requestTimeout.Seconds())
	perCall := requestTimeout + 5*time.Second
	if perCall < 15*time.Second {
		perCall = 15 * time.Second
	}
	attempt := func(name, action string, args []string) (string, *CheckResult) {
		callCtx, cancel := context.WithTimeout(ctx, perCall)
		defer cancel()
		out, err := a.runKubectl(callCtx, options, args...)
		if err == nil {
			return out, nil
		}
		stderr, stdout, timedOut := commandOutput(err)
		detail := strings.TrimSpace(stderr)
		if detail == "" {
			detail = strings.TrimSpace(stdout)
		}
		if detail == "" {
			detail = "kubectl failed"
		}
		category := classify(stderr, timedOut)
		result := failedCheck(name, fmt.Sprintf("could not %s: %s", action, truncate(sanitizeLines(detail), 500)), category)
		return out, &result
	}

	checks := make([]CheckResult, 0, 21)
	versions, connectivity := attempt("api-connectivity", "reach the Kubernetes API with the saved context", baseArgs(target, req, "api-versions"))
	served := map[string]bool{}
	if connectivity != nil {
		checks = append(checks, *connectivity)
	} else {
		checks = append(checks, okCheck("api-connectivity", "API reachable with saved context"))
		for _, line := range strings.Fields(versions) {
			served[line] = true
		}
	}
	groups := []struct {
		name, group, display string
		want                 []string
	}{
		{"agents-api", "agents.x-k8s.io", "Sandbox API agents.x-k8s.io/v1beta1", []string{"sandboxes"}},
		{"extensions-api", "extensions.agents.x-k8s.io", "Sandbox extensions API extensions.agents.x-k8s.io/v1beta1", []string{"sandboxclaims", "sandboxtemplates", "sandboxwarmpools"}},
	}
	for _, group := range groups {
		if connectivity == nil && !served[group.group+"/v1beta1"] {
			checks = append(checks, failedCheck(group.name, group.display+" is not served", "missing-infrastructure"))
			continue
		}
		out, result := attempt(group.name, "discover "+group.display, baseArgs(target, req, "api-resources", "--api-group="+group.group, "-o", "name"))
		if result != nil {
			checks = append(checks, *result)
			continue
		}
		missing := []string{}
		for _, resource := range group.want {
			if !strings.Contains(strings.ToLower(out), resource) {
				missing = append(missing, resource)
			}
		}
		if len(missing) > 0 {
			checks = append(checks, failedCheck(group.name, group.display+" served but missing: "+strings.Join(missing, ", "), "missing-infrastructure"))
		} else {
			checks = append(checks, okCheck(group.name, group.display+" served"))
		}
	}

	out, result := attempt("runtimeclass-gvisor", "read RuntimeClass gvisor", baseArgs(target, req, "get", "runtimeclass", "gvisor", "-o", "json"))
	if result != nil {
		checks = append(checks, *result)
	} else {
		var value struct {
			Handler string `json:"handler"`
		}
		if json.Unmarshal([]byte(out), &value) != nil {
			checks = append(checks, failedCheck("runtimeclass-gvisor", "RuntimeClass gvisor returned unreadable JSON", "unknown"))
		} else if !strings.Contains(strings.ToLower(value.Handler), "runsc") {
			checks = append(checks, failedCheck("runtimeclass-gvisor", fmt.Sprintf("RuntimeClass gvisor handler is %q, want runsc", value.Handler), "missing-infrastructure"))
		} else {
			checks = append(checks, okCheck("runtimeclass-gvisor", fmt.Sprintf("RuntimeClass gvisor present (handler %s)", value.Handler)))
		}
	}

	out, result = attempt("storage", "list StorageClasses", baseArgs(target, req, "get", "storageclass", "-o", "json"))
	if result != nil {
		checks = append(checks, *result)
	} else {
		var value struct {
			Items []struct {
				Metadata struct {
					Name        string            `json:"name"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal([]byte(out), &value) != nil {
			checks = append(checks, failedCheck("storage", "StorageClass list returned unreadable JSON", "unknown"))
		} else if len(value.Items) == 0 {
			checks = append(checks, failedCheck("storage", "no StorageClasses available for sandbox homes", "missing-infrastructure"))
		} else {
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
			checks = append(checks, okCheck("storage", fmt.Sprintf("%d StorageClass(es): %s%s", len(names), strings.Join(names, ", "), label)))
		}
	}

	_, result = attempt("namespace", fmt.Sprintf("read namespace %q", target.Namespace), baseArgs(target, req, "get", "namespace", target.Namespace, "-o", "json"))
	if result != nil {
		checks = append(checks, *result)
	} else {
		checks = append(checks, okCheck("namespace", fmt.Sprintf("namespace %q exists", target.Namespace)))
	}

	out, result = attempt("budgets-quota", "read ResourceQuotas in target namespace", namespacedArgs(target, req, "get", "resourcequota", "-o", "json"))
	if result != nil {
		checks = append(checks, *result)
	} else {
		checks = append(checks, quotaCheck(out))
	}
	out, result = attempt("budgets-limits", "read LimitRanges in target namespace", namespacedArgs(target, req, "get", "limitrange", "-o", "json"))
	if result != nil {
		value := *result
		value.Advisory = true
		checks = append(checks, value)
	} else {
		checks = append(checks, limitsCheck(out))
	}

	permissions := make([]CheckResult, len(requiredPermissions))
	group := new(errgroup.Group)
	group.SetLimit(6)
	for i, permission := range requiredPermissions {
		group.Go(func() error {
			permissions[i] = a.permissionCheck(ctx, target, options, req, perCall, permission)
			return nil
		})
	}
	_ = group.Wait()
	checks = append(checks, permissions...)
	report := CheckReport{Context: target.Context, Namespace: target.Namespace, OK: true, Checks: checks, CheckedAt: a.now().UTC()}
	for _, check := range checks {
		if !check.OK && !check.Advisory {
			report.OK = false
		}
	}
	return report
}

var computeQuota = regexp.MustCompile(`^(pods|cpu|memory|requests\.cpu|requests\.memory|limits\.cpu|limits\.memory|requests\.ephemeral-storage|limits\.ephemeral-storage)$`)
var storageQuota = regexp.MustCompile(`^(persistentvolumeclaims|requests\.storage)$`)

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
	keys := map[string]bool{}
	hasCompute, hasStorage := false, false
	for _, item := range value.Items {
		names = append(names, item.Metadata.Name)
		for key := range item.Spec.Hard {
			keys[key] = true
			hasCompute = hasCompute || computeQuota.MatchString(key)
			hasStorage = hasStorage || storageQuota.MatchString(key)
		}
	}
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
	keyList := make([]string, 0, len(keys))
	for key := range keys {
		keyList = append(keyList, key)
	}
	sort.Strings(keyList)
	hard := strings.Join(keyList, ", ")
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

func (a *App) permissionCheck(ctx context.Context, target KubeTarget, options globalOptions, req string, timeout time.Duration, permission permission) CheckResult {
	shown := permission.Resource
	if permission.Subresource != "" {
		shown += "/" + permission.Subresource
	}
	name := "perm-" + permission.Verb + "-" + shortResource(shown)
	args := []string{"auth", "can-i", permission.Verb, permission.Resource}
	if permission.Subresource != "" {
		args = append(args, "--subresource="+permission.Subresource)
	}
	if permission.Namespaced {
		args = namespacedArgs(target, req, args...)
	} else {
		args = baseArgs(target, req, args...)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := a.runKubectl(callCtx, options, args...)
	if err != nil {
		_, stdout, _ := commandOutput(err)
		if strings.TrimSpace(stdout) != "" {
			out = stdout
		}
	}
	answer := strings.ToLower(strings.TrimSpace(out))
	if answer == "yes" {
		return okCheck(name, fmt.Sprintf("can %s %s", permission.Verb, shown))
	}
	if answer == "no" || strings.HasPrefix(answer, "no ") {
		scope := "cluster scope"
		if permission.Namespaced {
			scope = "namespace"
		}
		result := failedCheck(name, fmt.Sprintf("cannot %s %s in %s", permission.Verb, shown, scope), "denied")
		result.Advisory = permission.Advisory
		return result
	}
	stderr, stdout, timedOut := commandOutput(err)
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = strings.TrimSpace(stdout)
	}
	if detail == "" {
		detail = sanitizeLines(out)
	}
	result := failedCheck(name, fmt.Sprintf("could not check permission %s %s: %s", permission.Verb, shown, truncate(sanitizeLines(detail), 500)), classify(stderr, timedOut))
	result.Advisory = permission.Advisory
	return result
}

func shortResource(value string) string {
	for _, suffix := range []string{".agents.x-k8s.io", ".extensions", ".storage.k8s.io", ".node.k8s.io"} {
		value = strings.ReplaceAll(value, suffix, "")
	}
	return strings.ReplaceAll(value, "/", "-")
}
func truncate(value string, size int) string {
	if len(value) <= size {
		return value
	}
	return value[:size]
}
