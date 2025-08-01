// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package software

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestMountUnmountHive(t *testing.T) {
	// Test mountHive with non-existent path
	err := mountHive("nonexistent/path/NTUSER.DAT")
	assert.Error(t, err)

	// Test unmountHive when no hive is mounted
	err = unmountHive()
	assert.Error(t, err)
}

func deleteRegistryKeyRecursive(t *testing.T, root registry.Key, path string) error {
	// Open the key
	key, err := registry.OpenKey(root, path, registry.ALL_ACCESS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to open key: %v", err)
	}
	defer func() { _ = key.Close() }()

	// List subkeys
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("failed to list subkeys: %v", err)
	}

	// Delete each subkey
	for _, subkey := range subkeys {
		fullPath := path + "\\" + subkey
		err = deleteRegistryKeyRecursive(t, root, fullPath)
		if err != nil {
			return err
		}
	}

	// Close the key before trying to delete it
	_ = key.Close()

	// Delete the key itself
	err = registry.DeleteKey(root, path)
	if err != nil {
		return fmt.Errorf("failed to delete key: %v", err)
	}

	return nil
}

func TestUnicodeCollectFromKey(t *testing.T) {
	// Create a test key in HKCU (safer than HKLM which requires admin rights)
	testRoot := "SOFTWARE\\DatadogTest\\WinSoftware"
	reg := registry.CURRENT_USER

	// Clean up any leftover test keys recursively
	err := deleteRegistryKeyRecursive(t, reg, testRoot)
	if err != nil {
		t.Logf("Initial cleanup error: %v", err)
	}

	// Ensure cleanup after test
	defer func() {
		err := deleteRegistryKeyRecursive(t, reg, testRoot)
		if err != nil {
			t.Logf("Final cleanup error: %v", err)
		}
	}()

	// Create test keys
	key, _, err := registry.CreateKey(reg, testRoot, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("Failed to create test registry key: %v", err)
	}

	// Test data with Unicode characters
	testData := []struct {
		subKey      string
		displayName string
		version     string
		publisher   string
	}{
		{
			subKey:      "{DEEFE46F-60F2-430B-AE0A-15A76E57B767}",
			displayName: "Contrôle d'intégrité du PC Windows",
			version:     "3.9.2402.14001",
			publisher:   "Microsoft Corporation",
		},
		{
			subKey:      "{TEST-UNICODE-2}",
			displayName: "プログラムと機能", // "Programs and Features" in Japanese
			version:     "1.0.0",
			publisher:   "テスト発行者", // "Test Publisher" in Japanese
		},
		{
			subKey:      "{TEST-UNICODE-3}",
			displayName: "Інсталятор Windows", // "Windows Installer" in Ukrainian
			version:     "2.0.0",
			publisher:   "тестовий видавець", // "Test Publisher" in Ukrainian
		},
	}

	// Create test subkeys with Unicode data
	var subKeys []registry.Key
	for _, td := range testData {
		subKey, _, err := registry.CreateKey(key, td.subKey, registry.ALL_ACCESS)
		if err != nil {
			t.Fatalf("Failed to create test subkey: %v", err)
		}
		subKeys = append(subKeys, subKey)

		err = subKey.SetStringValue("DisplayName", td.displayName)
		if err != nil {
			t.Fatalf("Failed to set DisplayName: %v", err)
		}

		err = subKey.SetStringValue("DisplayVersion", td.version)
		if err != nil {
			t.Fatalf("Failed to set DisplayVersion: %v", err)
		}

		err = subKey.SetStringValue("Publisher", td.publisher)
		if err != nil {
			t.Fatalf("Failed to set Publisher: %v", err)
		}
	}

	// Close all keys before testing
	for _, sk := range subKeys {
		_ = sk.Close()
	}
	_ = key.Close()

	entries, warnings := collectFromKey(reg, testRoot, registry.WOW64_64KEY)

	// Verify results
	assert.Empty(t, warnings, "Should not have warnings for valid registry data")
	assert.Len(t, entries, len(testData), "Should collect all test entries")

	// Verify each entry was collected correctly
	entryMap := make(map[string]*Entry)
	for _, entry := range entries {
		entryMap[entry.DisplayName] = entry
	}

	for _, td := range testData {
		entry, exists := entryMap[td.displayName]
		require.True(t, exists, "Entry for %s should exist", td.displayName)
		assert.Equal(t, td.displayName, entry.DisplayName, "DisplayName should match")
		assert.Equal(t, trimVersion(td.version), entry.Version, "Version should be trimmed")
		assert.Equal(t, "desktop", entry.Source, "Source should be registry")
		assert.True(t, entry.Is64Bit, "Should be marked as 64-bit for WOW64_64KEY")
		assert.Equal(t, td.publisher, entry.Publisher, "Publisher should match")
		assert.Equal(t, td.subKey, entry.ProductCode, "ProductCode should be subkey name")
	}
}

func TestTrimVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.2.3", "1.2.3"},
		{"01.02.03", "1.2.3"},
		{"1.0.0.0", "1.0.0.0"},
		{"01.00.00.00", "1.0.0.0"},
		{"16.0.12345.67890", "16.0.12345.67890"},
		// Some entries return empty strings - we consider them as "0"
		{"", "0"},
		{"1", "1"},
		{"01", "1"},
		{"1.2", "1.2"},
		{"01.02", "1.2"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%s", tt.input), func(t *testing.T) {
			result := trimVersion(tt.input)
			assert.Equal(t, tt.expected, result, "trimVersion(%q) should return %q", tt.input, tt.expected)
		})
	}
}
