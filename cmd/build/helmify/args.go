package main

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	controllerManagerDeployment = "gatekeeper-controller-manager"
	auditDeployment             = "gatekeeper-audit"
)

type argumentRule struct {
	name                string
	match               func(string) bool
	replacement         string
	helmDefaultArgument string
	omit                bool
}

type argumentConfig struct {
	rules                 []argumentRule
	helmOnly              []helmOnlyArgument
	allowedSourceOverlaps map[string]struct{}
}

type helmOnlyArgument struct {
	value      string
	identities []string
}

func transformExact(name, source, replacement string) argumentRule {
	return argumentRule{
		name: name,
		match: func(argument string) bool {
			return argument == source
		},
		replacement: replacement,
	}
}

func transformExactWithHelmDefault(name, source, replacement, helmDefaultArgument string) argumentRule {
	rule := transformExact(name, source, replacement)
	rule.helmDefaultArgument = helmDefaultArgument
	return rule
}

func transformFlag(name, flag, replacement string) argumentRule {
	return argumentRule{
		name: name,
		match: func(argument string) bool {
			return argument == flag || strings.HasPrefix(argument, flag+"=")
		},
		replacement: replacement,
	}
}

func omitExact(name, source string) argumentRule {
	return argumentRule{
		name: name,
		match: func(argument string) bool {
			return argument == source
		},
		omit: true,
	}
}

func helmArgument(value string) helmOnlyArgument {
	return helmOnlyArgument{value: value}
}

func helmTemplate(value string, identities ...string) helmOnlyArgument {
	return helmOnlyArgument{value: value, identities: identities}
}

func transformDeploymentArguments(object string) (string, string, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(object), &document); err != nil {
		return "", "", fmt.Errorf("parse object for argument transformation: %w", err)
	}

	root, err := documentRoot(&document)
	if err != nil {
		return "", "", err
	}
	if scalarValue(mappingValue(root, "kind")) != DeploymentKind {
		return object, "", nil
	}

	metadata := mappingValue(root, "metadata")
	name := scalarValue(mappingValue(metadata, "name"))
	var config argumentConfig
	switch name {
	case controllerManagerDeployment:
		config = controllerManagerArguments
	case auditDeployment:
		config = auditArguments
	default:
		return object, "", nil
	}

	containers := mappingValue(mappingValue(mappingValue(mappingValue(root, "spec"), "template"), "spec"), "containers")
	if containers == nil || containers.Kind != yaml.SequenceNode {
		return "", "", fmt.Errorf("deployment %q has no container list", name)
	}

	var manager *yaml.Node
	for _, container := range containers.Content {
		command := mappingValue(container, "command")
		if sequenceContains(command, "/manager") {
			if manager != nil {
				return "", "", fmt.Errorf("deployment %q has multiple containers using /manager", name)
			}
			manager = container
		}
	}
	if manager == nil {
		return "", "", fmt.Errorf("deployment %q has no container using /manager", name)
	}

	argsKey, args, nextKey := mappingEntry(manager, "args")
	if argsKey == nil || args == nil || args.Kind != yaml.SequenceNode {
		return "", "", fmt.Errorf("deployment %q manager container has no argument list", name)
	}

	source := make([]string, 0, len(args.Content))
	for _, argument := range args.Content {
		if argument.Kind != yaml.ScalarNode {
			return "", "", fmt.Errorf("deployment %q manager argument at line %d is not a scalar", name, argument.Line)
		}
		source = append(source, argument.Value)
	}
	rendered, err := transformArguments(name, source, config)
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(object, "\n")
	start := argsKey.Line - 1
	if start < 0 || start >= len(lines) {
		return "", "", fmt.Errorf("deployment %q argument line %d is outside the document", name, argsKey.Line)
	}
	keyOffset := argsKey.Column - 1
	if keyOffset < 0 || keyOffset > len(lines[start]) {
		return "", "", fmt.Errorf("deployment %q argument column %d is outside line %d", name, argsKey.Column, argsKey.Line)
	}
	keyPrefix := lines[start][:keyOffset]
	argumentIndent := strings.Repeat(" ", keyOffset)
	var end int
	if nextKey != nil {
		end = nextKey.Line - 1
	} else {
		end = argumentBlockEnd(lines, start, len(argumentIndent))
	}

	replacement := make([]string, 0, len(rendered)+1)
	replacement = append(replacement, keyPrefix+"args:")
	for _, argument := range rendered {
		replacement = append(replacement, argumentIndent+"- "+argument)
	}

	lines = append(lines[:start], append(replacement, lines[end:]...)...)
	return strings.Join(lines, "\n"), name, nil
}

func transformArguments(deployment string, source []string, config argumentConfig) ([]string, error) {
	helmOnlyIdentities, err := validateHelmOnlyArguments(deployment, config.helmOnly)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(source)+len(config.helmOnly))
	counts := make([]int, len(config.rules))

	for _, argument := range source {
		match, err := matchingRule(deployment, argument, config.rules)
		if err != nil {
			return nil, err
		}
		if match == -1 {
			encoded, err := encodeArgument(deployment, argument)
			if err != nil {
				return nil, err
			}
			result = append(result, encoded)
			continue
		}

		counts[match]++
		if counts[match] > 1 {
			return nil, fmt.Errorf("deployment %q has multiple %s arguments", deployment, config.rules[match].name)
		}
		if !config.rules[match].omit {
			result = append(result, config.rules[match].replacement)
		}
	}

	for i, rule := range config.rules {
		if counts[i] == 0 {
			return nil, fmt.Errorf("deployment %q is missing its %s argument", deployment, rule.name)
		}
	}

	for i, argument := range config.helmOnly {
		identities := helmOnlyIdentities[i]
		for _, identity := range identities {
			for _, sourceArgument := range source {
				if !argumentIdentityMatches(identity, sourceArgument) || config.allowsSourceOverlap(sourceArgument) {
					continue
				}
				return nil, fmt.Errorf(
					"deployment %q source argument %q conflicts with Helm-only argument %q; add a transformation rule",
					deployment, sourceArgument, identity,
				)
			}
		}
		result = append(result, argument.value)
	}
	return result, nil
}

func matchingRule(deployment, argument string, rules []argumentRule) (int, error) {
	match := -1
	for i, rule := range rules {
		if !rule.match(argument) {
			continue
		}
		if match != -1 {
			return -1, fmt.Errorf("deployment %q argument %q matches multiple transformation rules", deployment, argument)
		}
		match = i
	}
	return match, nil
}

func encodeArgument(deployment, argument string) (string, error) {
	if strings.ContainsAny(argument, "\r\n") {
		return "", fmt.Errorf("deployment %q argument %q contains a line break", deployment, argument)
	}
	if strings.Contains(argument, "{{") {
		return "", fmt.Errorf(
			"deployment %q passthrough argument %q contains Helm template syntax; add an explicit transformation rule",
			deployment,
			argument,
		)
	}
	if strings.Contains(argument, "HELMSUBST") {
		return "", fmt.Errorf(
			"deployment %q passthrough argument %q contains a reserved Helm substitution marker; add an explicit transformation rule",
			deployment,
			argument,
		)
	}
	encoded, err := yaml.Marshal(argument)
	if err != nil {
		return "", fmt.Errorf("encode deployment %q argument %q: %w", deployment, argument, err)
	}
	return strings.TrimSuffix(string(encoded), "\n"), nil
}

func argumentFlag(argument string) (string, bool) {
	if !strings.HasPrefix(argument, "--") {
		return "", false
	}
	if index := strings.IndexByte(argument, '='); index >= 0 {
		return argument[:index], true
	}
	return argument, true
}

func (argument helmOnlyArgument) collisionIdentities() ([]string, error) {
	if len(argument.identities) > 0 {
		for _, identity := range argument.identities {
			if _, ok := argumentFlag(identity); !ok {
				return nil, fmt.Errorf("helm template %q has invalid emitted argument identity %q", argument.value, identity)
			}
		}
		return argument.identities, nil
	}
	flag, ok := argumentFlag(argument.value)
	if !ok {
		return nil, fmt.Errorf("helm template %q has no emitted argument identities", argument.value)
	}
	return []string{flag}, nil
}

func validateHelmOnlyArguments(deployment string, arguments []helmOnlyArgument) ([][]string, error) {
	identities := make([][]string, len(arguments))
	type owner struct {
		identity string
		value    string
	}
	owners := make([]owner, 0, len(arguments))

	for i, argument := range arguments {
		current, err := argument.collisionIdentities()
		if err != nil {
			return nil, fmt.Errorf("deployment %q: %w", deployment, err)
		}
		for _, identity := range current {
			for _, existing := range owners {
				if !argumentIdentitiesOverlap(identity, existing.identity) {
					continue
				}
				return nil, fmt.Errorf(
					"deployment %q Helm-only arguments %q and %q have overlapping identities %q and %q",
					deployment,
					existing.value,
					argument.value,
					existing.identity,
					identity,
				)
			}
			owners = append(owners, owner{identity: identity, value: argument.value})
		}
		identities[i] = current
	}
	return identities, nil
}

func argumentIdentitiesOverlap(first, second string) bool {
	return argumentIdentityMatches(first, second) || argumentIdentityMatches(second, first)
}

func argumentIdentityMatches(identity, argument string) bool {
	if strings.Contains(identity, "=") {
		return argument == identity
	}
	flag, ok := argumentFlag(argument)
	return ok && flag == identity
}

func (config argumentConfig) allowsSourceOverlap(argument string) bool {
	flag, ok := argumentFlag(argument)
	if !ok {
		return false
	}
	_, allowed := config.allowedSourceOverlaps[flag]
	return allowed
}

func argumentBlockEnd(lines []string, start, indent int) int {
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		currentIndent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		if currentIndent < indent || currentIndent == indent && !strings.HasPrefix(trimmed, "-") {
			return i
		}
	}
	return len(lines)
}

func documentRoot(document *yaml.Node) (*yaml.Node, error) {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected a YAML document with a mapping root")
	}
	return document.Content[0], nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func mappingEntry(mapping *yaml.Node, key string) (keyNode, valueNode, nextKey *yaml.Node) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, nil, nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != key {
			continue
		}
		if i+2 < len(mapping.Content) {
			nextKey = mapping.Content[i+2]
		}
		return mapping.Content[i], mapping.Content[i+1], nextKey
	}
	return nil, nil, nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func sequenceContains(sequence *yaml.Node, value string) bool {
	if sequence == nil || sequence.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range sequence.Content {
		if item.Kind == yaml.ScalarNode && item.Value == value {
			return true
		}
	}
	return false
}
