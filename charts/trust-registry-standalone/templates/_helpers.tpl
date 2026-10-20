{{- define "tr.fullname" -}}
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
