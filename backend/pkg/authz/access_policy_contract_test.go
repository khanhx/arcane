package authz_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/getarcaneapp/arcane/backend/internal/services"
	"github.com/getarcaneapp/arcane/backend/pkg/authz"
	"github.com/stretchr/testify/require"
)

func TestAccessSurfaceCategoryRegistryCoversBackendCategories(t *testing.T) {
	hiddenSettingsCategories := map[string]struct{}{
		"security": {},
	}

	for _, category := range services.NewSettingsSearchService().GetSettingsCategories() {
		if _, hidden := hiddenSettingsCategories[category.ID]; hidden {
			continue
		}
		_, ok := authz.AccessSurfaceByID("settings.category." + category.ID)
		require.True(t, ok, "settings category %s must have an access surface", category.ID)
	}

	for _, category := range services.NewCustomizeSearchService().GetCustomizeCategories() {
		_, ok := authz.AccessSurfaceByID("customize.category." + category.ID)
		require.True(t, ok, "customize category %s must have an access surface", category.ID)
	}
}

func TestPublishedAccessSurfaceURLsHaveFrontendRoutes(t *testing.T) {
	routesRoot := filepath.Join(repoRootInternal(t), "frontend", "src", "routes", "(app)")

	for _, surface := range authz.AccessSurfaces() {
		if surface.URL == "" {
			continue
		}
		routePath := frontendRoutePathInternal(routesRoot, surface.URL)
		_, err := os.Stat(routePath)
		require.NoError(t, err, "access surface %s URL %s must map to frontend route %s", surface.ID, surface.URL, routePath)
	}
}

func TestFrontendNavigationReferencesKnownAccessSurfaces(t *testing.T) {
	navPath := filepath.Join(repoRootInternal(t), "frontend", "src", "lib", "config", "navigation-config.ts")
	body, err := os.ReadFile(navPath)
	require.NoError(t, err)

	matches := regexp.MustCompile(`accessSurfaceId:\s*'([^']+)'`).FindAllStringSubmatch(string(body), -1)
	require.NotEmpty(t, matches)

	for _, match := range matches {
		require.Len(t, match, 2)
		_, ok := authz.AccessSurfaceByID(match[1])
		require.True(t, ok, "frontend navigation references unknown access surface %s", match[1])
	}
}

func repoRootInternal(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}

func frontendRoutePathInternal(routesRoot, url string) string {
	parts := strings.Split(strings.Trim(url, "/"), "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			parts[i] = "[" + strings.Trim(part, "{}") + "]"
			continue
		}
		if strings.HasPrefix(part, ":") {
			parts[i] = "[" + strings.TrimPrefix(part, ":") + "]"
		}
	}
	return filepath.Join(append([]string{routesRoot}, parts...)...)
}
