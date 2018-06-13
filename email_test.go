package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidationEmailText(t *testing.T) {
	content := validationEmailText("example.com", []string{"mx.example.com, .mx.example.com"}, "abcd", time.Now(),
		"https://fake.starttls-everywhere.website")
	if !strings.Contains(content, "https://fake.starttls-everywhere.website/validate?abcd") {
		t.Errorf("E-mail formatted incorrectly.")
	}
}

func shouldPanic(t *testing.T, message string) {
	if r := recover(); r == nil {
		t.Errorf(message)
	}
}

func TestRequireMissingEnvPanics(t *testing.T) {
	defer shouldPanic(t, "requireEnv should have panicked")
	requireEnv("FAKE_ENV_VAR")
}
