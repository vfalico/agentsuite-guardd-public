{{- define "guardd.installationName" -}}
{{- $name := .Values.installationName -}}
{{- if not $name -}}
{{- $name = printf "%s-g-%s" (.Release.Name | trunc 24 | trimSuffix "-") (.Release.Name | sha256sum | trunc 10) -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$" $name) -}}
{{- fail "guardd installationName must be a DNS label of at most 39 characters" -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{- define "guardd.retention" -}}
helm.sh/resource-policy: keep
{{- end -}}

{{- define "guardd.installerPod" -}}
{{- $root := .root -}}
{{- $name := include "guardd.installationName" $root -}}
serviceAccountName: {{ $name }}-installer
restartPolicy: Never
nodeSelector:
  {{- toYaml $root.Values.nodeSelector | nindent 2 }}
{{- with $root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- range . }}
  - name: {{ . | quote }}
  {{- end }}
{{- end }}
securityContext:
  runAsUser: 0
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: reconcile
    image: {{ $root.Values.image | quote }}
    imagePullPolicy: {{ $root.Values.imagePullPolicy }}
    command: ["/opt/guardd/venv/bin/agentsuite-guardd"]
    args:
      - reconcile-kubernetes-installation
      - --namespace
      - {{ $root.Release.Namespace | quote }}
      - --installation
      - {{ $name | quote }}
      {{- if .stop }}
      - --disable-enrollment
      {{- end }}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      requests:
        cpu: 25m
        memory: 32Mi
      limits:
        cpu: "1"
        memory: 256Mi
{{- end -}}
