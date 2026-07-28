{{- define "csr-approver.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "csr-approver.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "csr-approver.labels" -}}
helm.sh/chart: {{ include "csr-approver.chart" . }}
{{ include "csr-approver.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ quote .Chart.AppVersion }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "csr-approver.selectorLabels" -}}
app.kubernetes.io/name: {{ include "csr-approver.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "csr-approver.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "csr-approver.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "csr-approver.needsMachineRole" -}}
{{- $needsMachineRole := false -}}
{{- range .Values.approvalRules -}}
{{- if eq .machineValidation "required" -}}
{{- $needsMachineRole = true -}}
{{- end -}}
{{- end -}}
{{- $needsMachineRole }}
{{- end -}}
