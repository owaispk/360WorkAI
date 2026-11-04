{{- define "workai360.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "workai360.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- define "workai360.labels" -}}
app.kubernetes.io/name: {{ include "workai360.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "workai360.secretName" -}}{{ default (printf "%s-secrets" (include "workai360.fullname" .)) .Values.existingSecret }}{{- end -}}
{{- define "workai360.image" -}}{{ .repository }}:{{ .tag | default $.appVersion }}{{- end -}}
{{- define "workai360.securityContext" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 1654
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: [ALL] }
{{- end -}}
{{/* Settings shared by the API pods and the migration job. */}}
{{- define "workai360.apiEnv" -}}
- { name: ASPNETCORE_URLS, value: "http://+:8080" }
- { name: Database__Provider, value: mysql }
- { name: Database__AutoMigrate, value: "false" }
- { name: Auth__WebUrl, value: {{ .Values.webUrl | quote }} }
- { name: Auth__ApiPublicUrl, value: {{ .Values.apiPublicUrl | quote }} }
{{- range $i, $p := .Values.trustedProxies }}
- { name: Auth__TrustedProxies__{{ $i }}, value: {{ $p | quote }} }
{{- end }}
- name: Auth__Secret
  valueFrom: { secretKeyRef: { name: {{ include "workai360.secretName" . }}, key: auth-secret } }
- name: ConnectionStrings__Default
  valueFrom: { secretKeyRef: { name: {{ include "workai360.secretName" . }}, key: database-connection-string } }
- { name: Email__Provider, value: smtp }
- { name: Email__From, value: {{ .Values.email.from | quote }} }
- { name: Email__Smtp__Host, value: {{ .Values.email.smtp.host | quote }} }
- { name: Email__Smtp__Port, value: {{ .Values.email.smtp.port | quote }} }
- { name: Email__Smtp__Security, value: {{ .Values.email.smtp.security | quote }} }
{{- with .Values.email.smtp.username }}
- { name: Email__Smtp__User, value: {{ . | quote }} }
- name: Email__Smtp__Password
  valueFrom: { secretKeyRef: { name: {{ include "workai360.secretName" $ }}, key: smtp-password } }
{{- end }}
{{- if .Values.redis.enabled }}
- name: Cache__Redis__ConnectionString
  valueFrom: { secretKeyRef: { name: {{ include "workai360.secretName" . }}, key: redis-connection-string } }
{{- end }}
{{- if .Values.gateway.enabled }}
- { name: Gateway__Enabled, value: "true" }
- { name: Gateway__LiteLlm__BaseUrl, value: {{ .Values.gateway.litellm.baseUrl | quote }} }
{{- with .Values.gateway.litellm.publicUrl }}
- { name: Gateway__LiteLlm__PublicUrl, value: {{ . | quote }} }
{{- end }}
- name: Gateway__LiteLlm__MasterKey
  valueFrom: { secretKeyRef: { name: {{ include "workai360.secretName" . }}, key: litellm-master-key } }
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}
