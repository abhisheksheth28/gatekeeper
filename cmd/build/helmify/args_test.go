package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestTransformArgumentsPreservesUnknownSourceArguments(t *testing.T) {
	source := []string{
		"--port=8443",
		"--logtostderr",
		`--future=value=with,commas {braces} "quotes"`,
		"--exempt-namespace=gatekeeper-system",
		"--operation=webhook",
		"--operation=mutation-webhook",
		"--disable-opa-builtin={http.send}",
	}

	got, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments)
	if err != nil {
		t.Fatal(err)
	}

	assertContains(t, got, `--future=value=with,commas {braces} "quotes"`)
	assertContains(t, got, "HELMSUBST_CONTROLLER_MANAGER_WEBHOOK_OPERATION")
	assertContains(t, got, "HELMSUBST_CONTROLLER_MANAGER_GENERATE_OPERATION")
	assertContains(t, got, "HELMSUBST_MUTATION_ENABLED_ARG")
	assertContains(t, got, "HELMSUBST_DEPLOYMENT_CONTROLLER_MANAGER_DISABLED_BUILTIN")
}

func TestTransformAuditArgumentsDerivesEverySourceOperation(t *testing.T) {
	source := []string{
		"--operation=audit",
		"--operation=status",
		"--operation=mutation-status",
		"--operation=generate",
		"--logtostderr",
		"--disable-opa-builtin={http.send}",
		"--disable-cert-rotation",
	}

	got, err := transformArguments(auditDeployment, source, auditArguments)
	if err != nil {
		t.Fatal(err)
	}

	assertContains(t, got, "HELMSUBST_AUDIT_OPERATION")
	assertContains(t, got, "HELMSUBST_STATUS_OPERATION")
	assertContains(t, got, "HELMSUBST_MUTATION_STATUS_ENABLED_ARG")
	assertContains(t, got, "HELMSUBST_AUDIT_GENERATE_OPERATION")
	assertNotContains(t, got, "--disable-opa-builtin={http.send}")
	assertNotContains(t, got, "HELMSUBST_DEPLOYMENT_CONTROLLER_MANAGER_DISABLED_BUILTIN")
}

func TestTransformArgumentsRejectsMissingAndDuplicateRequiredArguments(t *testing.T) {
	source := []string{
		"--port=8443",
		"--port=9443",
		"--logtostderr",
		"--exempt-namespace=gatekeeper-system",
		"--operation=webhook",
		"--operation=mutation-webhook",
		"--disable-opa-builtin={http.send}",
	}
	if _, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments); err == nil ||
		!strings.Contains(err.Error(), "multiple webhook port arguments") {
		t.Fatalf("got error %v, want a duplicate webhook port error", err)
	}

	source = source[1:]
	source = source[:len(source)-1]
	if _, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments); err == nil ||
		!strings.Contains(err.Error(), "missing its disabled OPA builtins argument") {
		t.Fatalf("got error %v, want a missing disabled builtins error", err)
	}
}

func TestTransformArgumentsRejectsHelmOnlyFlagCollision(t *testing.T) {
	tests := []struct {
		name      string
		argument  string
		conflicts string
	}{
		{
			name:      "literal Helm argument",
			argument:  "--health-addr=:9090",
			conflicts: "--health-addr",
		},
		{
			name:      "templated Helm argument",
			argument:  "--emit-admission-events=true",
			conflicts: "--emit-admission-events",
		},
		{
			name:      "exact Helm operation",
			argument:  "--operation=generate",
			conflicts: "--operation=generate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := []string{
				"--port=8443",
				"--logtostderr",
				test.argument,
				"--exempt-namespace=gatekeeper-system",
				"--operation=webhook",
				"--operation=mutation-webhook",
				"--disable-opa-builtin={http.send}",
			}

			_, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf(
				"source argument %q conflicts with Helm-only argument %q",
				test.argument,
				test.conflicts,
			)) {
				t.Fatalf("got error %v, want a Helm-only argument collision error", err)
			}
		})
	}
}

func TestTransformArgumentsRejectsHelmOnlyCollisionWithTransformedArgument(t *testing.T) {
	source := []string{
		"--port=8443",
		"--logtostderr",
		"--exempt-namespace=gatekeeper-system",
		"--operation=webhook",
		"--operation=mutation-webhook",
		"--disable-opa-builtin={http.send}",
	}
	config := controllerManagerArguments
	config.helmOnly = append([]helmOnlyArgument{}, config.helmOnly...)
	config.helmOnly = append(config.helmOnly, helmArgument("--port=9443"))

	_, err := transformArguments(controllerManagerDeployment, source, config)
	if err == nil || !strings.Contains(err.Error(), `source argument "--port=8443" conflicts with Helm-only argument "--port"`) {
		t.Fatalf("got error %v, want a transformed argument collision error", err)
	}
}

func TestTransformArgumentsRejectsOverlappingHelmOnlyArguments(t *testing.T) {
	config := argumentConfig{
		helmOnly: []helmOnlyArgument{
			helmArgument("--log-file=/tmp/gatekeeper.log"),
			helmTemplate("HELMSUBST_SECOND_LOG_FILE", "--log-file"),
		},
	}

	_, err := transformArguments("test", nil, config)
	if err == nil || !strings.Contains(err.Error(), `have overlapping identities "--log-file" and "--log-file"`) {
		t.Fatalf("got error %v, want an overlapping Helm-only identity error", err)
	}
}

func TestTransformArgumentsAllowsDistinctExactHelmOnlyArguments(t *testing.T) {
	config := argumentConfig{
		helmOnly: []helmOnlyArgument{
			helmTemplate("HELMSUBST_GENERATE_OPERATION", "--operation=generate"),
			helmTemplate("HELMSUBST_FUTURE_OPERATION", "--operation=future"),
		},
	}

	got, err := transformArguments("test", nil, config)
	if err != nil {
		t.Fatal(err)
	}
	assertContains(t, got, "HELMSUBST_GENERATE_OPERATION")
	assertContains(t, got, "HELMSUBST_FUTURE_OPERATION")
}

func TestTransformArgumentsRejectsAdditionalSourceDisabledBuiltin(t *testing.T) {
	source := []string{
		"--port=8443",
		"--logtostderr",
		"--operation=webhook",
		"--operation=mutation-webhook",
		"--disable-opa-builtin={http.send}",
		"--disable-opa-builtin={net.lookup_ip_addr}",
		"--exempt-namespace=gatekeeper-system",
	}

	_, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments)
	if err == nil || !strings.Contains(err.Error(), "multiple disabled OPA builtins arguments") {
		t.Fatalf("got error %v, want a duplicate disabled builtins error", err)
	}
}

func TestTransformArgumentsAllowsExplicitSourceOverlaps(t *testing.T) {
	source := []string{
		"--port=8443",
		"--logtostderr",
		"--exempt-namespace=gatekeeper-system",
		"--exempt-namespace=policy-system",
		"--operation=future-operation",
		"--operation=webhook",
		"--operation=mutation-webhook",
		"--disable-opa-builtin={http.send}",
	}

	got, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments)
	if err != nil {
		t.Fatal(err)
	}
	assertContains(t, got, "--exempt-namespace=policy-system")
	assertContains(t, got, "--operation=future-operation")
}

func TestHelmOnlyArgumentConfiguration(t *testing.T) {
	configurations := map[string]argumentConfig{
		controllerManagerDeployment: controllerManagerArguments,
		auditDeployment:             auditArguments,
	}
	for deployment, config := range configurations {
		t.Run(deployment, func(t *testing.T) {
			for _, argument := range config.helmOnly {
				for _, identity := range argument.identities {
					if !strings.HasPrefix(identity, "--") {
						t.Errorf("argument %q has invalid emitted identity %q", argument.value, identity)
					}
				}
				if _, literal := argumentFlag(argument.value); literal {
					continue
				}

				var replacement string
				found := false
				for marker, candidate := range replacements {
					if strings.TrimSpace(marker) == "- "+argument.value {
						replacement = candidate
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Helm template marker %q has no replacement", argument.value)
					continue
				}
				emitted := emittedTemplateArguments(replacement)
				for _, identity := range argument.identities {
					found := false
					for _, candidate := range emitted {
						if argumentIdentityMatches(identity, candidate) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf(
							"Helm template marker %q declares identity %q not found in its replacement",
							argument.value,
							identity,
						)
					}
				}
				for _, candidate := range emitted {
					declared := false
					for _, identity := range argument.identities {
						if argumentIdentityMatches(identity, candidate) {
							declared = true
							break
						}
					}
					if !declared {
						t.Errorf(
							"Helm template marker %q emits argument %q without declaring its identity",
							argument.value,
							candidate,
						)
					}
				}
			}
		})
	}

	for marker, replacement := range replacements {
		if len(emittedTemplateArguments(replacement)) == 0 {
			continue
		}

		argumentMarker, found := strings.CutPrefix(strings.TrimSpace(marker), "- ")
		if !found {
			t.Errorf("argument-emitting replacement %q is not keyed by an argument marker", marker)
			continue
		}

		registered := false
		for _, config := range configurations {
			for _, rule := range config.rules {
				if rule.replacement == argumentMarker {
					registered = true
					break
				}
			}
			for _, argument := range config.helmOnly {
				if argument.value == argumentMarker {
					registered = true
					break
				}
			}
		}
		if !registered {
			t.Errorf("argument-emitting replacement %q is not registered by any workload configuration", marker)
		}
	}
}

func TestEmittedTemplateArguments(t *testing.T) {
	replacement := `{{ if .Values.inline }}- --inline={{ .Values.inline }}{{- end }}
        - --operation=generate
        {{ fail "message mentioning --not-an-argument" }}`

	got := emittedTemplateArguments(replacement)
	want := []string{"--inline=", "--operation=generate"}
	if !slices.Equal(got, want) {
		t.Fatalf("emitted arguments = %q, want %q", got, want)
	}
}

func TestTransformDeploymentArgumentsUsesManagerCommand(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-controller-manager
spec:
  template:
    spec:
      containers:
      - name: '{{ .Chart.Name }}'
        command:
        - /manager
        args:
        - --port=8443
        - --logtostderr
        - --exempt-namespace=gatekeeper-system
        - --operation=webhook
        - --operation=mutation-webhook
        - --disable-opa-builtin={http.send}
        image: gatekeeper
      - name: sidecar
        args:
        - --leave-me-alone
        image: sidecar
`

	got, transformedDeployment, err := transformDeploymentArguments(input)
	if err != nil {
		t.Fatal(err)
	}
	if transformedDeployment != controllerManagerDeployment {
		t.Fatalf("transformed deployment %q, want %q", transformedDeployment, controllerManagerDeployment)
	}
	if !strings.Contains(got, "        args:\n        - --port=HELMSUBST_DEPLOYMENT_CONTROLLER_MANAGER_PORT") {
		t.Fatalf("transformed manager arguments not found:\n%s", got)
	}
	if !strings.Contains(got, "        image: gatekeeper") {
		t.Fatalf("field following the manager arguments was lost:\n%s", got)
	}
	if !strings.Contains(got, "        - --leave-me-alone") {
		t.Fatalf("sidecar arguments were changed:\n%s", got)
	}
}

func TestTransformDeploymentArgumentsPreservesSequenceItemPrefixWhenArgumentsAreFirst(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-controller-manager
spec:
  template:
    spec:
      containers:
      - args:
        - --port=8443
        - --logtostderr
        - --exempt-namespace=gatekeeper-system
        - --operation=webhook
        - --operation=mutation-webhook
        - --disable-opa-builtin={http.send}
        command:
        - /manager
`

	got, _, err := transformDeploymentArguments(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "      - args:\n        - --port=HELMSUBST_DEPLOYMENT_CONTROLLER_MANAGER_PORT") {
		t.Fatalf("transformed argument list lost its sequence item prefix:\n%s", got)
	}
	if !strings.Contains(got, "        command:\n        - /manager") {
		t.Fatalf("container command following the arguments was lost:\n%s", got)
	}

	var document yaml.Node
	if err := yaml.Unmarshal([]byte(got), &document); err != nil {
		t.Fatalf("transformed deployment is invalid YAML: %v\n%s", err, got)
	}
}

func TestTransformDeploymentArgumentsRejectsAmbiguousManagerContainer(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-audit
spec:
  template:
    spec:
      containers:
      - command: [/manager]
      - command: [/manager]
`

	if _, _, err := transformDeploymentArguments(input); err == nil ||
		!strings.Contains(err.Error(), "multiple containers using /manager") {
		t.Fatalf("got error %v, want an ambiguous manager container error", err)
	}
}

func TestTransformDeploymentArgumentsPreservesFieldsAfterArgsLastContainerField(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-audit
spec:
  template:
    spec:
      containers:
      - command: [/manager]
        args:
        - --operation=audit
        - --operation=status
        - --operation=mutation-status
        - --operation=generate
        - --logtostderr
        - --disable-opa-builtin={http.send}
        - --disable-cert-rotation
      nodeSelector:
        kubernetes.io/os: linux
`

	got, _, err := transformDeploymentArguments(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "      nodeSelector:\n        kubernetes.io/os: linux") {
		t.Fatalf("pod fields following an args-last container were lost:\n%s", got)
	}
}

func TestTransformArgumentsRejectsMultilineUnknownArgument(t *testing.T) {
	source := []string{
		"--port=8443",
		"--logtostderr",
		"--future=line1\nline2",
		"--exempt-namespace=gatekeeper-system",
		"--operation=webhook",
		"--operation=mutation-webhook",
		"--disable-opa-builtin={http.send}",
	}

	if _, err := transformArguments(controllerManagerDeployment, source, controllerManagerArguments); err == nil ||
		!strings.Contains(err.Error(), "contains a line break") {
		t.Fatalf("got error %v, want a multiline argument error", err)
	}
}

func TestEncodeArgumentRejectsReservedHelmSyntax(t *testing.T) {
	tests := []struct {
		name     string
		argument string
		want     string
	}{
		{
			name:     "Helm template",
			argument: "--future={{ .Values.future }}",
			want:     "contains Helm template syntax",
		},
		{
			name:     "Helm substitution marker",
			argument: "--future=HELMSUBST_FUTURE",
			want:     "contains a reserved Helm substitution marker",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := encodeArgument(controllerManagerDeployment, test.argument)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestEncodeArgumentAcceptsStaticSyntax(t *testing.T) {
	for _, argument := range []string{
		"--future=value",
		"--disable-opa-builtin={http.send}",
	} {
		t.Run(argument, func(t *testing.T) {
			if _, err := encodeArgument(controllerManagerDeployment, argument); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareOutputDirectory(t *testing.T) {
	t.Run("creates missing directory", func(t *testing.T) {
		destination := filepath.Join(t.TempDir(), "chart")

		if err := prepareOutputDirectory(destination); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			t.Fatalf("output path %q is not a directory", destination)
		}
	})

	t.Run("accepts empty directory", func(t *testing.T) {
		if err := prepareOutputDirectory(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rejects non-empty directory without modifying it", func(t *testing.T) {
		destination := t.TempDir()
		sentinel := filepath.Join(destination, "keep-me")
		want := []byte("unchanged")
		if err := os.WriteFile(sentinel, want, 0o600); err != nil {
			t.Fatal(err)
		}

		err := prepareOutputDirectory(destination)
		if err == nil || !strings.Contains(err.Error(), "is not empty") {
			t.Fatalf("got error %v, want a non-empty output directory error", err)
		}
		got, err := os.ReadFile(sentinel)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("existing file contents = %q, want %q", got, want)
		}
	})
}

func TestRunRejectsNonEmptyOutputBeforeReadingInput(t *testing.T) {
	destination := t.TempDir()
	sentinel := filepath.Join(destination, "Chart.yaml")
	want := []byte("existing chart")
	if err := os.WriteFile(sentinel, want, 0o600); err != nil {
		t.Fatal(err)
	}

	err := run(errorReader{}, destination)
	if err == nil || !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("got error %v, want a non-empty output directory error", err)
	}
	got, readErr := os.ReadFile(sentinel)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("existing file contents = %q, want %q", got, want)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("input must not be read")
}

func TestRunReturnsTransformationErrors(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-controller-manager
spec:
  template:
    spec:
      containers:
      - command: [/manager]
        args: [--port=8443]
`

	err := run(strings.NewReader(input), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "missing its system namespace exemption argument") {
		t.Fatalf("got error %v, want a source argument validation error", err)
	}
}

func TestRunRequiresEverySharedDeploymentExactlyOnce(t *testing.T) {
	controllerManager := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: gatekeeper-controller-manager
spec:
  template:
    spec:
      containers:
      - command: [/manager]
        args:
        - --port=8443
        - --logtostderr
        - --exempt-namespace=gatekeeper-system
        - --operation=webhook
        - --operation=mutation-webhook
        - --disable-opa-builtin={http.send}
`

	err := run(strings.NewReader(controllerManager), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `expected to transform deployment "gatekeeper-audit" exactly once, found 0`) {
		t.Fatalf("got error %v, want a missing audit deployment error", err)
	}

	err = run(strings.NewReader(controllerManager+"\n---\n"+controllerManager), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `expected to transform deployment "gatekeeper-controller-manager" exactly once, found 2`) {
		t.Fatalf("got error %v, want a duplicate controller-manager deployment error", err)
	}
}

func TestRunRejectsRenamedSharedDeployments(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: renamed-controller-manager
spec:
  template:
    spec:
      containers:
      - command: [/manager]
        args:
        - --port=8443
`

	err := run(strings.NewReader(input), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `expected to transform deployment "gatekeeper-controller-manager" exactly once, found 0`) {
		t.Fatalf("got error %v, want an unrecognized deployment error", err)
	}
}

func TestStaticManifestCanBeTransformed(t *testing.T) {
	contents, err := os.ReadFile("../../../manifest_staging/deploy/gatekeeper.yaml")
	if err != nil {
		t.Fatal(err)
	}

	transformed := 0
	for _, object := range strings.Split(string(contents), "\n---\n") {
		got, _, err := transformDeploymentArguments(object)
		if err != nil {
			t.Fatal(err)
		}
		if got != object {
			transformed++
		}
	}
	if transformed != 2 {
		t.Fatalf("transformed %d Deployments from static manifest, want 2", transformed)
	}
}

// helmDefaultOnlyArguments lists arguments that the default Helm chart emits
// but the static manifest omits. Each entry must equal the manager's built-in
// default so static and Helm installations behave the same. Add behavior-changing
// defaults to config/manager/manager.yaml instead.
var helmDefaultOnlyArguments = map[string][]string{
	controllerManagerDeployment: {
		"--health-addr=:9090",
		"--prometheus-port=8888",
		"--log-denies=false",
		"--admission-events-involved-namespace=false",
		"--log-level=INFO",
		"--enable-external-data=true",
		"--enable-generator-resource-expansion=true",
		"--log-mutations=false",
		"--mutation-annotations=false",
		"--disable-cert-rotation=false",
		"--max-serving-threads=-1",
		"--tls-min-version=1.3",
		"--validating-webhook-configuration-name=gatekeeper-validating-webhook-configuration",
		"--mutating-webhook-configuration-name=gatekeeper-mutating-webhook-configuration",
		"--external-data-provider-response-cache-ttl=3m",
		"--enable-k8s-native-validation=true",
		"--metrics-backend=prometheus",
	},
	auditDeployment: {
		"--audit-interval=60",
		"--log-level=INFO",
		"--constraint-violations-limit=20",
		"--validating-webhook-configuration-name=gatekeeper-validating-webhook-configuration",
		"--mutating-webhook-configuration-name=gatekeeper-mutating-webhook-configuration",
		"--audit-from-cache=false",
		"--audit-chunk-size=500",
		"--audit-match-kind-only=false",
		"--audit-events-involved-namespace=false",
		"--audit-connection=audit-connection",
		"--audit-channel=audit-channel",
		"--health-addr=:9090",
		"--prometheus-port=8888",
		"--enable-external-data=true",
		"--enable-generator-resource-expansion=true",
		"--metrics-backend=prometheus",
		"--external-data-provider-response-cache-ttl=3m",
		"--enable-k8s-native-validation=true",
	},
}

func TestDefaultHelmArgumentsMatchStaticManifest(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("GATEKEEPER_REQUIRE_HELM") == "true" {
			t.Fatal("helm is required but was not found in PATH")
		}
		t.Skip("helm is not installed")
	}

	staticManifest, err := os.Open("../../../manifest_staging/deploy/gatekeeper.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := staticManifest.Close(); err != nil {
			t.Errorf("close static manifest: %v", err)
		}
	})

	staticArguments, err := readDeploymentArguments(staticManifest, map[string]string{
		controllerManagerDeployment: controllerManagerDeployment,
		auditDeployment:             auditDeployment,
	})
	if err != nil {
		t.Fatal(err)
	}

	chart, err := filepath.Abs("../../../manifest_staging/charts/gatekeeper")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helm, "template", "gatekeeper", chart, "--namespace", "gatekeeper-system")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	rendered, err := command.Output()
	if err != nil {
		t.Fatalf("render default Helm chart: %v\n%s", err, stderr.String())
	}

	renderedArguments, err := readDeploymentArguments(bytes.NewReader(rendered), map[string]string{
		controllerManagerDeployment: controllerManagerDeployment,
		auditDeployment:             auditDeployment,
	})
	if err != nil {
		t.Fatal(err)
	}

	for deployment, config := range map[string]argumentConfig{
		controllerManagerDeployment: controllerManagerArguments,
		auditDeployment:             auditArguments,
	} {
		t.Run(deployment, func(t *testing.T) {
			expected, err := expectedDefaultArguments(deployment, staticArguments[deployment], config)
			if err != nil {
				t.Fatal(err)
			}
			expected = append(expected, helmDefaultOnlyArguments[deployment]...)
			missing, unexpected := defaultArgumentDifferences(expected, renderedArguments[deployment])
			if len(missing) > 0 || len(unexpected) > 0 {
				t.Errorf(
					"default Helm arguments differ from the static manifest:\nmissing: %q\nunexpected: %q\n"+
						"Add defaults that change behavior to config/manager/manager.yaml. Update "+
						"helmDefaultOnlyArguments only when the argument equals the manager's built-in default.",
					missing,
					unexpected,
				)
			}
		})
	}
}

func TestExpectedDefaultArguments(t *testing.T) {
	config := argumentConfig{
		rules: []argumentRule{
			transformExact("unchanged default", "--unchanged", "HELMSUBST_UNCHANGED"),
			transformExactWithHelmDefault(
				"different Helm default",
				"--different=source",
				"HELMSUBST_DIFFERENT",
				"--different=helm",
			),
			omitExact("omitted default", "--omitted"),
		},
	}
	source := []string{"--unchanged", "--different=source", "--omitted", "--inherited"}

	got, err := expectedDefaultArguments("test", source, config)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--unchanged", "--different=helm", "--inherited"}
	if !slices.Equal(got, want) {
		t.Fatalf("expected default arguments = %q, want %q", got, want)
	}
}

func TestDefaultArgumentDifferencesDetectsChangedDuplicateAndUnpinnedDefaults(t *testing.T) {
	missing, unexpected := defaultArgumentDifferences(
		[]string{"--port=8443", "--logtostderr", "--health-addr=:9090"},
		[]string{"--port=9443", "--logtostderr", "--logtostderr", "--health-addr=:9090", "--operation=generate"},
	)
	if !slices.Equal(missing, []string{"--port=8443"}) {
		t.Errorf("missing arguments = %q, want [--port=8443]", missing)
	}
	want := []string{"--port=9443", "--logtostderr", "--operation=generate"}
	if !slices.Equal(unexpected, want) {
		t.Errorf("unexpected arguments = %q, want %q", unexpected, want)
	}
}

func TestHelmOverlayDoesNotReplaceSourceArgumentLists(t *testing.T) {
	contents, err := os.ReadFile("kustomize-for-helm.yaml")
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, object := range strings.Split(string(contents), "\n---\n") {
		var document yaml.Node
		if err := yaml.Unmarshal([]byte(object), &document); err != nil {
			t.Fatal(err)
		}
		root, err := documentRoot(&document)
		if err != nil {
			t.Fatal(err)
		}
		if scalarValue(mappingValue(root, "kind")) != DeploymentKind {
			continue
		}
		name := scalarValue(mappingValue(mappingValue(root, "metadata"), "name"))
		if name != controllerManagerDeployment && name != auditDeployment {
			continue
		}
		found++

		containers := mappingValue(mappingValue(mappingValue(mappingValue(root, "spec"), "template"), "spec"), "containers")
		for _, container := range containers.Content {
			if mappingValue(container, "args") != nil {
				t.Fatalf("Helm overlay Deployment %q must not define a complete argument list", name)
			}
		}
	}
	if found != 2 {
		t.Fatalf("found %d shared Deployment patches, want 2", found)
	}
}

func readDeploymentArguments(reader io.Reader, names map[string]string) (map[string][]string, error) {
	arguments := make(map[string][]string, len(names))
	decoder := yaml.NewDecoder(reader)
	for {
		var document struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Command []string `yaml:"command"`
							Args    []string `yaml:"args"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode manifests: %w", err)
		}
		if document.Kind != DeploymentKind {
			continue
		}
		normalizedName, selected := names[document.Metadata.Name]
		if !selected {
			continue
		}
		if _, duplicate := arguments[normalizedName]; duplicate {
			return nil, fmt.Errorf("deployment %q appears multiple times", document.Metadata.Name)
		}

		var managerArguments []string
		for _, container := range document.Spec.Template.Spec.Containers {
			if !slices.Contains(container.Command, "/manager") {
				continue
			}
			if managerArguments != nil {
				return nil, fmt.Errorf("deployment %q has multiple containers using /manager", document.Metadata.Name)
			}
			managerArguments = container.Args
		}
		if managerArguments == nil {
			return nil, fmt.Errorf("deployment %q has no container using /manager", document.Metadata.Name)
		}
		arguments[normalizedName] = managerArguments
	}

	for sourceName, normalizedName := range names {
		if _, found := arguments[normalizedName]; !found {
			return nil, fmt.Errorf("deployment %q was not found", sourceName)
		}
	}
	return arguments, nil
}

func expectedDefaultArguments(deployment string, source []string, config argumentConfig) ([]string, error) {
	if _, err := transformArguments(deployment, source, config); err != nil {
		return nil, err
	}

	expected := make([]string, 0, len(source))
	for _, argument := range source {
		match, err := matchingRule(deployment, argument, config.rules)
		if err != nil {
			return nil, err
		}
		if match >= 0 {
			rule := config.rules[match]
			if rule.omit {
				continue
			}
			if rule.helmDefaultArgument != "" {
				expected = append(expected, rule.helmDefaultArgument)
				continue
			}
		}
		expected = append(expected, argument)
	}
	return expected, nil
}

func defaultArgumentDifferences(expected, rendered []string) ([]string, []string) {
	remaining := append([]string(nil), rendered...)
	var missing []string
	for _, argument := range expected {
		index := slices.Index(remaining, argument)
		if index == -1 {
			missing = append(missing, argument)
			continue
		}
		remaining = slices.Delete(remaining, index, index+1)
	}
	return missing, remaining
}

func emittedTemplateArguments(replacement string) []string {
	fields := strings.Fields(replacement)
	var arguments []string
	for i := 1; i < len(fields); i++ {
		if !strings.HasSuffix(fields[i-1], "-") || !strings.HasPrefix(fields[i], "--") {
			continue
		}
		argument := fields[i]
		if template := strings.Index(argument, "{{"); template >= 0 {
			argument = argument[:template]
		}
		argument = strings.TrimRight(argument, `"'`)
		if _, ok := argumentFlag(argument); ok {
			arguments = append(arguments, argument)
		}
	}
	return arguments
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Errorf("values do not contain %q:\n%q", want, values)
}

func assertNotContains(t *testing.T, values []string, unwanted string) {
	t.Helper()
	for _, value := range values {
		if value == unwanted {
			t.Errorf("values unexpectedly contain %q:\n%q", unwanted, values)
			return
		}
	}
}
