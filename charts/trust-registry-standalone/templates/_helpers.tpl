{{- define "tr.fullname" -}}
{{- if not (regexMatch "^[a-z][a-z0-9-]*$" .Release.Name) -}}
{{- fail "release name must start with a letter and contain only lowercase letters, digits, and hyphens for signed local service endpoints" -}}
{{- end -}}
{{- if gt (len .Release.Name) 47 -}}
{{- fail "release name must be at most 47 characters so signed local service endpoints are not truncated" -}}
{{- end -}}
{{- printf "%s-tr" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "tr.componentName" -}}
{{- printf "%s-%s" (include "tr.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tr.labels" -}}
app.kubernetes.io/name: trust-registry-standalone
app.kubernetes.io/instance: {{ .root.Release.Name | quote }}
app.kubernetes.io/part-of: trust-registry-standalone
app.kubernetes.io/component: {{ .component | quote }}
{{- end -}}

{{- define "tr.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name | quote }}
app.kubernetes.io/part-of: trust-registry-standalone
app.kubernetes.io/component: {{ .component | quote }}
{{- end -}}
