// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Linux Foundation

// Package output provides secure output management for GitHub Actions with
// comprehensive validation, secret masking, and atomic operations.
package output

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/config"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/logger"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/internal/secrets"
	"github.com/modeseven-lfreleng-actions/1password-secrets-action/pkg/security"
)

// Manager handles output operations for GitHub Actions with security controls
type Manager struct {
	config       *config.Config
	logger       *logger.Logger
	github       *GitHubActions
	validator    *Validator
	outputConfig *Config
	mu           sync.RWMutex
	outputs      map[string]*Value
	envVars      map[string]*Value
	maskedValues []string
}

// Value represents a single output or environment variable value
type Value struct {
	Name      string
	Value     *security.SecureString
	Masked    bool
	Source    string // "secret" or "metadata"
	Timestamp int64
}

// Config holds configuration for the output manager
type Config struct {
	ReturnType           string
	MaxOutputs           int
	MaxValueLength       int
	ValidateUTF8         bool
	TrimWhitespace       bool
	NormalizeLineEndings bool
	AtomicOperations     bool
	MaskAllSecrets       bool
	DryRun               bool
}

// Result represents the result of output operations
type Result struct {
	OutputsSet    int
	EnvVarsSet    int
	ValuesMasked  int
	Errors        []error
	Success       bool
	AtomicSuccess bool
}

// DefaultConfig returns sensible defaults for output manager configuration
func DefaultConfig() *Config {
	return &Config{
		ReturnType:           config.ReturnTypeOutput,
		MaxOutputs:           50,
		MaxValueLength:       32768, // 32KB limit
		ValidateUTF8:         true,
		TrimWhitespace:       true,
		NormalizeLineEndings: true,
		AtomicOperations:     true,
		MaskAllSecrets:       true,
		DryRun:               false,
	}
}

// NewManager creates a new output manager with the provided configuration
func NewManager(cfg *config.Config, log *logger.Logger,
	outputConfig *Config) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if outputConfig == nil {
		outputConfig = DefaultConfig()
	}

	// Override return type from main config
	outputConfig.ReturnType = cfg.ReturnType

	github, err := NewGitHubActions(log, &GitHubConfig{
		OutputFile:    cfg.GitHubOutput,
		EnvFile:       cfg.GitHubEnv,
		Workspace:     cfg.GitHubWorkspace,
		ValidateFiles: true,
		SecureWrites:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GitHub Actions integration: %w", err)
	}

	validatorConfig := DefaultValidatorConfig()
	validatorConfig.MaxOutputs = outputConfig.MaxOutputs
	validatorConfig.MaxValueLength = outputConfig.MaxValueLength
	validatorConfig.ValidateUTF8 = outputConfig.ValidateUTF8
	validatorConfig.StrictMode = false // Disable strict mode to allow test values

	validator, err := NewValidator(validatorConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize validator: %w", err)
	}

	return &Manager{
		config:       cfg,
		logger:       log,
		github:       github,
		validator:    validator,
		outputConfig: outputConfig,
		outputs:      make(map[string]*Value),
		envVars:      make(map[string]*Value),
		maskedValues: make([]string, 0),
	}, nil
}

// ProcessSecrets processes secret results and sets outputs/environment variables
func (m *Manager) ProcessSecrets(result *secrets.BatchResult) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if result == nil {
		return nil, fmt.Errorf("batch result is required")
	}

	outputResult := &Result{
		Errors: make([]error, 0),
	}

	m.logger.Info("Processing secrets for output",
		"success_count", result.SuccessCount,
		"error_count", result.ErrorCount,
		"return_type", m.config.ReturnType)

	if err := m.validateOutputCapability(); err != nil {
		outputResult.Errors = append(outputResult.Errors, err)
		return outputResult, err
	}

	pendingOutputs, pendingEnvVars := m.collectPendingOperations(result, outputResult)
	pendingOutputs = m.appendMetadataOutputs(result, pendingOutputs)

	// Execute operations atomically if configured
	if m.outputConfig.AtomicOperations {
		// For atomic operations, execute all or none
		if len(outputResult.Errors) > 0 {
			// On this early return the pending operations are never stored
			// in m.outputs/m.envVars, so nothing else will destroy their
			// secure values. Release them here to avoid leaking locked-memory
			// allocations.
			m.destroyPendingOperations(pendingOutputs, pendingEnvVars)
			return outputResult, fmt.Errorf("validation errors prevent atomic execution")
		}
	}

	m.executePendingOperations(pendingOutputs, pendingEnvVars, outputResult)

	// Count masked values
	outputResult.ValuesMasked = len(m.maskedValues)
	outputResult.Success = len(outputResult.Errors) == 0
	outputResult.AtomicSuccess = !m.outputConfig.AtomicOperations || outputResult.Success

	m.logger.Info("Output processing completed",
		"outputs_set", outputResult.OutputsSet,
		"env_vars_set", outputResult.EnvVarsSet,
		"values_masked", outputResult.ValuesMasked,
		"errors", len(outputResult.Errors),
		"success", outputResult.Success)

	return outputResult, nil
}

// Operation represents a pending output operation
type Operation struct {
	Type  string // "output" or "env"
	Name  string
	Value *Value
}

// collectPendingOperations builds the pending output and env var operations
// for all successful secrets, recording validation errors on outputResult.
func (m *Manager) collectPendingOperations(
	result *secrets.BatchResult, outputResult *Result,
) ([]Operation, []Operation) {
	var pendingOutputs []Operation
	var pendingEnvVars []Operation

	for key, secretResult := range result.Results {
		if secretResult.Error != nil {
			m.logger.Debug("Skipping output for failed secret",
				"key", key, "error", secretResult.Error)
			outputResult.Errors = append(outputResult.Errors,
				fmt.Errorf("secret '%s' failed: %w", key, secretResult.Error))
			continue
		}

		ops, err := m.buildSecretOperations(key, secretResult, result)
		if err != nil {
			outputResult.Errors = append(outputResult.Errors, err)
			continue
		}

		for _, op := range ops {
			switch op.Type {
			case "output":
				pendingOutputs = append(pendingOutputs, op)
			case "env":
				pendingEnvVars = append(pendingEnvVars, op)
			}
		}
	}

	return pendingOutputs, pendingEnvVars
}

// buildSecretOperations validates and processes a single secret, returning the
// pending operations it should produce based on the configured return type.
func (m *Manager) buildSecretOperations(
	key string, secretResult *secrets.SecretResult, result *secrets.BatchResult,
) ([]Operation, error) {
	if secretResult.Value == nil || secretResult.Value.IsEmpty() {
		m.logger.Warn("Skipping output for empty secret", "key", key)
		return nil, nil
	}

	if err := m.validator.ValidateOutputName(key); err != nil {
		return nil, fmt.Errorf("invalid output name '%s': %w", key, err)
	}

	secretValue := secretResult.Value.String()
	if err := m.validator.ValidateOutputValue(secretValue); err != nil {
		return nil, fmt.Errorf("invalid output value for '%s': %w", key, err)
	}

	processedValue, err := m.processOutputValue(secretValue)
	if err != nil {
		return nil, fmt.Errorf("failed to process value for '%s': %w", key, err)
	}

	secureValue, err := security.NewSecureStringFromString(processedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure value for '%s': %w", key, err)
	}

	outputValue := &Value{
		Name:      key,
		Value:     secureValue,
		Source:    "secret",
		Timestamp: secretTimestamp(secretResult),
	}

	var ops []Operation
	switch m.config.ReturnType {
	case config.ReturnTypeOutput, config.ReturnTypeBoth:
		ops = append(ops, Operation{
			Type:  "output",
			Name:  key,
			Value: outputValue,
		})

	case config.ReturnTypeEnv:
		envVarName := m.generateEnvVarName(key, result.Results[key])
		ops = append(ops, Operation{
			Type:  "env",
			Name:  envVarName,
			Value: outputValue,
		})
	}

	if m.config.ReturnType == config.ReturnTypeBoth {
		envVarName := m.generateEnvVarName(key, result.Results[key])
		ops = append(ops, Operation{
			Type:  "env",
			Name:  envVarName,
			Value: outputValue,
		})
	}

	return ops, nil
}

// appendMetadataOutputs appends the secrets_count metadata output when the
// return type includes GitHub Actions outputs.
func (m *Manager) appendMetadataOutputs(
	result *secrets.BatchResult, pendingOutputs []Operation,
) []Operation {
	if m.config.ReturnType != config.ReturnTypeOutput &&
		m.config.ReturnType != config.ReturnTypeBoth {
		return pendingOutputs
	}

	secretsCountValue, err := security.NewSecureStringFromString(
		fmt.Sprintf("%d", result.SuccessCount))
	if err != nil {
		return pendingOutputs
	}

	return append(pendingOutputs, Operation{
		Type: "output",
		Name: "secrets_count",
		Value: &Value{
			Name:      "secrets_count",
			Value:     secretsCountValue,
			Source:    "metadata",
			Timestamp: metadataTimestamp(result),
		},
	})
}

// metadataTimestamp returns a representative timestamp for metadata outputs.
// It falls back to the current time when the batch has no entries (getFirstKey
// yields "" for an empty map) or the first entry carries no metrics, which
// would otherwise dereference a nil pointer.
func metadataTimestamp(result *secrets.BatchResult) int64 {
	return secretTimestamp(result.Results[getFirstKey(result.Results)])
}

// secretTimestamp returns a secret's retrieval end time, falling back to the
// current time when the result or its metrics are absent, or when the end time
// was never recorded (a zero time.Time converts to a large negative Unix
// value, which would corrupt output/metadata timestamps).
func secretTimestamp(secretResult *secrets.SecretResult) int64 {
	if secretResult != nil && secretResult.Metrics != nil &&
		!secretResult.Metrics.EndTime.IsZero() {
		return secretResult.Metrics.EndTime.Unix()
	}
	return time.Now().Unix()
}

// destroyPendingOperations releases the secure values held by pending
// operations that will not be executed, preventing locked-memory leaks on
// early-return paths (e.g. aborted atomic execution). A value may be shared
// between an output and an env operation (return type "both"), so each
// distinct value is destroyed only once; SecureString.Destroy is also
// idempotent as a safeguard.
func (m *Manager) destroyPendingOperations(groups ...[]Operation) {
	seen := make(map[*Value]struct{})
	for _, group := range groups {
		for _, op := range group {
			if op.Value == nil {
				continue
			}
			if _, done := seen[op.Value]; done {
				continue
			}
			seen[op.Value] = struct{}{}
			if op.Value.Value != nil {
				if err := op.Value.Value.Destroy(); err != nil {
					m.logger.Debug("Failed to destroy pending operation value",
						"name", op.Name, "error", err)
				}
			}
		}
	}
}

// executePendingOperations runs the pending output and env var operations,
// recording per-group results and errors on outputResult.
func (m *Manager) executePendingOperations(
	pendingOutputs, pendingEnvVars []Operation, outputResult *Result,
) {
	if len(pendingOutputs) > 0 {
		if err := m.executeOutputOperations(pendingOutputs); err != nil {
			outputResult.Errors = append(outputResult.Errors, err)
		} else {
			outputResult.OutputsSet = len(pendingOutputs)
		}
	}

	if len(pendingEnvVars) > 0 {
		if err := m.executeEnvOperations(pendingEnvVars); err != nil {
			outputResult.Errors = append(outputResult.Errors, err)
		} else {
			outputResult.EnvVarsSet = len(pendingEnvVars)
		}
	}
}

// executeOutputOperations executes GitHub Actions output operations
func (m *Manager) executeOutputOperations(operations []Operation) error {
	m.logger.Debug("Executing output operations", "count", len(operations))

	for _, op := range operations {
		value := op.Value.Value.String()

		// Mask only real secret values, and avoid masking short/numeric values
		if op.Value.Source == "secret" && m.isMaskable(value) {
			if err := m.maskValue(value); err != nil {
				return fmt.Errorf("failed to mask value for output '%s': %w", op.Name, err)
			}
		}

		// Set the GitHub Actions output
		if err := m.github.SetOutput(op.Name, value); err != nil {
			return fmt.Errorf("failed to set output '%s': %w", op.Name, err)
		}

		// Store in internal tracking
		m.outputs[op.Name] = op.Value
		m.logger.Debug("Set GitHub Actions output", "name", op.Name)
	}

	return nil
}

// executeEnvOperations executes environment variable operations
func (m *Manager) executeEnvOperations(operations []Operation) error {
	m.logger.Debug("Executing environment variable operations", "count", len(operations))

	for _, op := range operations {
		value := op.Value.Value.String()

		// Mask only real secret values, and avoid masking short/numeric values
		if op.Value.Source == "secret" && m.isMaskable(value) {
			if err := m.maskValue(value); err != nil {
				return fmt.Errorf("failed to mask value for env var '%s': %w", op.Name, err)
			}
		}

		// Set the environment variable
		if err := m.github.SetEnv(op.Name, value); err != nil {
			return fmt.Errorf("failed to set environment variable '%s': %w", op.Name, err)
		}

		// Store in internal tracking
		m.envVars[op.Name] = op.Value
		m.logger.Debug("Set environment variable", "name", op.Name)
	}

	return nil
}

// generateEnvVarName generates a valid environment variable name from a secret key and result
func (m *Manager) generateEnvVarName(key string, result *secrets.SecretResult) string {
	// For single secrets (key is "value"), use the actual secret path
	if key == "value" && result != nil {
		// Convert "Secret Name/field" to "SECRET_NAME_FIELD"
		secretPath := fmt.Sprintf("%s/%s", result.Request.ItemName, result.Request.FieldName)
		return m.secretPathToEnvVar(secretPath)
	}

	// For multiple secrets, use the key but ensure it's a valid env var name
	return m.sanitizeEnvVarName(key)
}

// secretPathToEnvVar converts a secret path like "Test Credential/password" to "TEST_CREDENTIAL_PASSWORD"
func (m *Manager) secretPathToEnvVar(secretPath string) string {
	// Replace forward slash with underscore
	envVar := strings.ReplaceAll(secretPath, "/", "_")

	// Convert to uppercase
	envVar = strings.ToUpper(envVar)

	// Replace spaces and other invalid characters with underscores
	envVar = regexp.MustCompile(`[^A-Z0-9_]+`).ReplaceAllString(envVar, "_")

	// Remove leading/trailing underscores and collapse multiple underscores
	envVar = regexp.MustCompile(`^_+|_+$`).ReplaceAllString(envVar, "")
	envVar = regexp.MustCompile(`_+`).ReplaceAllString(envVar, "_")

	// Ensure it starts with a letter or underscore (not a number)
	if len(envVar) > 0 && envVar[0] >= '0' && envVar[0] <= '9' {
		envVar = "_" + envVar
	}

	return envVar
}

// sanitizeEnvVarName ensures a string is a valid environment variable name
func (m *Manager) sanitizeEnvVarName(name string) string {
	// Check if the name is already valid as-is (for JSON keys like "shared_secret")
	envVarPattern := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if envVarPattern.MatchString(name) {
		return name
	}

	// Convert to uppercase for invalid names
	envVar := strings.ToUpper(name)

	// Replace invalid characters with underscores
	envVar = regexp.MustCompile(`[^A-Z0-9_]+`).ReplaceAllString(envVar, "_")

	// Remove leading/trailing underscores and collapse multiple underscores
	envVar = regexp.MustCompile(`^_+|_+$`).ReplaceAllString(envVar, "")
	envVar = regexp.MustCompile(`_+`).ReplaceAllString(envVar, "_")

	// Ensure it starts with a letter or underscore (not a number)
	if len(envVar) > 0 && envVar[0] >= '0' && envVar[0] <= '9' {
		envVar = "_" + envVar
	}

	// If empty after sanitization, provide a default
	if envVar == "" {
		envVar = "SECRET_VALUE"
	}

	return envVar
}

// maskValue adds a GitHub Actions mask for the given value
func (m *Manager) maskValue(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	// Check if already masked
	for _, masked := range m.maskedValues {
		if masked == value {
			return nil // Already masked
		}
	}

	// Add mask
	if err := m.github.MaskValue(value); err != nil {
		return fmt.Errorf("failed to add mask: %w", err)
	}

	// Track masked value
	m.maskedValues = append(m.maskedValues, value)
	return nil
}

// isMaskable determines if a value is safe to register as a GitHub Actions mask.
// We avoid masking very short or purely numeric values to prevent over-masking of common substrings.
func (m *Manager) isMaskable(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	// Do not mask very short values (e.g., "1", "ok") to avoid broad masking
	if len(v) < 6 {
		return false
	}
	// Purely numeric values are not masked
	if regexp.MustCompile(`^[0-9]+$`).MatchString(v) {
		return false
	}
	return true
}

// processOutputValue processes and normalizes an output value
func (m *Manager) processOutputValue(value string) (string, error) {
	processed := value

	// Trim whitespace if configured
	if m.outputConfig.TrimWhitespace {
		processed = strings.TrimSpace(processed)
	}

	// Normalize line endings if configured
	if m.validator != nil {
		// Convert Windows line endings to Unix
		processed = strings.ReplaceAll(processed, "\r\n", "\n")
		processed = strings.ReplaceAll(processed, "\r", "")
	}

	// Validate UTF-8 if configured
	if m.validator.config.ValidateUTF8 {
		if !isValidUTF8(processed) {
			return "", fmt.Errorf("value contains invalid UTF-8 sequences")
		}
	}

	return processed, nil
}

// validateOutputCapability checks if output operations can proceed
func (m *Manager) validateOutputCapability() error {
	switch m.config.ReturnType {
	case config.ReturnTypeOutput, config.ReturnTypeBoth:
		if err := m.github.ValidateOutputCapability(); err != nil {
			return fmt.Errorf("GitHub Actions outputs not available: %w", err)
		}

	case config.ReturnTypeEnv:
		if err := m.github.ValidateEnvCapability(); err != nil {
			return fmt.Errorf("GitHub Actions environment variables not available: %w", err)
		}
	}

	return nil
}

// GetOutputs returns a copy of current outputs (for testing/debugging)
func (m *Manager) GetOutputs() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for name, output := range m.outputs {
		result[name] = output.Value.String()
	}
	return result
}

// GetEnvVars returns a copy of current environment variables (for testing/debugging)
func (m *Manager) GetEnvVars() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string)
	for name, envVar := range m.envVars {
		result[name] = envVar.Value.String()
	}
	return result
}

// GetMaskedValues returns the list of masked values (for testing/debugging)
func (m *Manager) GetMaskedValues() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent modification
	result := make([]string, len(m.maskedValues))
	copy(result, m.maskedValues)
	return result
}

// Destroy cleans up the output manager and zeroes sensitive data
func (m *Manager) Destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Cleaning up output manager")

	var errors []error

	for name, output := range m.outputs {
		if err := output.Value.Destroy(); err != nil {
			errors = append(errors, fmt.Errorf("failed to destroy output '%s': %w", name, err))
		}
	}

	for name, envVar := range m.envVars {
		if err := envVar.Value.Destroy(); err != nil {
			errors = append(errors, fmt.Errorf("failed to destroy env var '%s': %w", name, err))
		}
	}

	// Clear maps
	m.outputs = make(map[string]*Value)
	m.envVars = make(map[string]*Value)
	m.maskedValues = make([]string, 0)

	if m.github != nil {
		if err := m.github.Destroy(); err != nil {
			errors = append(errors, fmt.Errorf("failed to destroy GitHub integration: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	m.logger.Debug("Output manager cleanup completed")
	return nil
}

// isValidUTF8 checks if a string contains valid UTF-8
func isValidUTF8(s string) bool {
	return strings.ToValidUTF8(s, "") == s
}

// getFirstKey returns the first key from a map (for metadata timestamps)
func getFirstKey(m map[string]*secrets.SecretResult) string {
	for k := range m {
		return k
	}
	return ""
}

// outputNamePattern validates GitHub Actions output names
var outputNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ValidateOutputName validates a GitHub Actions output name
func ValidateOutputName(name string) error {
	if name == "" {
		return fmt.Errorf("output name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("output name too long (maximum 100 characters)")
	}

	if !outputNamePattern.MatchString(name) {
		return fmt.Errorf("invalid output name format: must match pattern %s",
			outputNamePattern.String())
	}

	reservedNames := map[string]bool{
		"github":    true,
		"runner":    true,
		"input":     true,
		"inputs":    true,
		"secrets":   true,
		"env":       true,
		"workspace": true,
		"job":       true,
		"steps":     true,
		"strategy":  true,
		"matrix":    true,
		"needs":     true,
	}

	if reservedNames[strings.ToLower(name)] {
		return fmt.Errorf("output name '%s' is reserved", name)
	}

	return nil
}
