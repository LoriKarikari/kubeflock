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
{{- if gt (int .Values.sandbox.resources.cpuRequestMillicores) (int .Values.sandbox.resources.cpuLimitMillicores) -}}
{{- fail "sandbox.resources.cpuRequestMillicores cannot exceed cpuLimitMillicores" -}}
{{- end -}}
{{- if gt (int .Values.sandbox.resources.memoryRequestMi) (int .Values.sandbox.resources.memoryLimitMi) -}}
{{- fail "sandbox.resources.memoryRequestMi cannot exceed memoryLimitMi" -}}
{{- end -}}
{{- end }}
