{{- define "kubeflock.labels" -}}
app.kubernetes.io/name: kubeflock
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "kubeflock.validate" -}}
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
