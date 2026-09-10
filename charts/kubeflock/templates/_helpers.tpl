{{- define "kubeflock.labels" -}}
app.kubernetes.io/name: kubeflock
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "kubeflock.validate" -}}
{{- range .Values.access.subjects }}
{{- if has (lower .name) (list "system:authenticated" "system:unauthenticated" "system:serviceaccounts") }}
{{- fail (printf "access.subjects %q grants every identity in the cluster; list explicit users, groups, or service accounts" .name) }}
{{- end }}
{{- end }}
{{- $credentialNames := dict -}}
{{- $credentialEnvironments := dict -}}
{{- range .Values.credentials -}}
{{- if hasKey $credentialNames .name -}}
{{- fail (printf "credentials contains duplicate name %q" .name) -}}
{{- end -}}
{{- if hasKey $credentialEnvironments .environment -}}
{{- fail (printf "credentials contains duplicate environment %q" .environment) -}}
{{- end -}}
{{- $_ := set $credentialNames .name true -}}
{{- $_ := set $credentialEnvironments .environment true -}}
{{- end -}}
{{- if gt (int .Values.sandbox.resources.cpuRequestMillicores) (int .Values.sandbox.resources.cpuLimitMillicores) -}}
{{- fail "sandbox.resources.cpuRequestMillicores cannot exceed cpuLimitMillicores" -}}
{{- end -}}
{{- if gt (int .Values.sandbox.resources.memoryRequestMi) (int .Values.sandbox.resources.memoryLimitMi) -}}
{{- fail "sandbox.resources.memoryRequestMi cannot exceed memoryLimitMi" -}}
{{- end -}}
{{- if lt (int .Values.capacity.maxRetainedHomes) (int .Values.capacity.maxActiveSandboxes) -}}
{{- fail "capacity.maxRetainedHomes cannot be less than maxActiveSandboxes" -}}
{{- end -}}
{{- end }}
