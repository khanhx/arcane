package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessSurfaceRegistryDefinesSettingsCustomizeAndLandingSemantics(t *testing.T) {
	webhooks := requireAccessSurfaceInternal(t, "settings.category.webhooks")
	require.Equal(t, AccessSurfaceKindSettingsCategory, webhooks.Kind)
	require.Equal(t, "/settings/webhooks", webhooks.URL)
	require.Equal(t, AccessModePermissions, webhooks.AccessMode)
	require.Equal(t, AccessMatchModeAnyOf, webhooks.MatchMode)
	require.Equal(t, AccessScopeModeSelectedEnvPlusGlobal, webhooks.ScopeMode)
	require.ElementsMatch(t, []string{PermWebhooksList}, webhooks.Permissions)

	apiKeys := requireAccessSurfaceInternal(t, "settings.category.apikeys")
	require.Equal(t, AccessScopeModeGlobalOnly, apiKeys.ScopeMode)
	require.ElementsMatch(t, []string{PermApiKeysList, PermApiKeysRead}, apiKeys.Permissions)

	jobSchedule := requireAccessSurfaceInternal(t, "settings.category.jobschedule")
	require.Equal(t, AccessScopeModeSelectedEnvPlusGlobal, jobSchedule.ScopeMode)
	require.Equal(t, "/settings/jobs", jobSchedule.URL)
	require.ElementsMatch(t, []string{PermJobsManage}, jobSchedule.Permissions)

	templates := requireAccessSurfaceInternal(t, "customize.category.templates")
	require.Equal(t, AccessSurfaceKindCustomizeCategory, templates.Kind)
	require.Equal(t, AccessScopeModeGlobalOnly, templates.ScopeMode)
	require.ElementsMatch(t, []string{PermCustomizeManage, PermTemplatesList, PermTemplatesRead}, templates.Permissions)

	settingsLanding := requireAccessSurfaceInternal(t, "landing.settings")
	require.Equal(t, AccessSurfaceKindLanding, settingsLanding.Kind)
	require.Equal(t, "/settings", settingsLanding.URL)
	require.Equal(t, AccessModeAnyChild, settingsLanding.AccessMode)
	require.Contains(t, settingsLanding.Children, "settings.category.webhooks")
	require.Contains(t, settingsLanding.Children, "settings.category.apikeys")
	require.Contains(t, settingsLanding.Children, "settings.category.jobschedule")

	dashboard := requireAccessSurfaceInternal(t, "route.dashboard")
	require.Equal(t, AccessSurfaceKindRoute, dashboard.Kind)
	require.Equal(t, "/dashboard", dashboard.URL)
	require.Positive(t, dashboard.FallbackOrder)
}

func TestCanAccessSurfaceEvaluatesScopeModesAndLandingChildren(t *testing.T) {
	ps := NewPermissionSet()
	ps.AddEnv("env-a", PermWebhooksList)

	require.True(t, CanAccessSurface(ps, "settings.category.webhooks", "env-a"))
	require.True(t, CanAccessSurface(ps, "landing.settings", "env-a"))
	require.False(t, CanAccessSurface(ps, "settings.category.webhooks", "env-b"))
	require.False(t, CanAccessSurface(ps, "landing.settings", "env-b"))

	ps.AddGlobal(PermApiKeysRead)
	require.True(t, CanAccessSurface(ps, "settings.category.apikeys", "env-b"))
	require.True(t, CanAccessSurface(ps, "landing.settings", "env-b"))

	jobsPS := NewPermissionSet()
	jobsPS.AddEnv("env-a", PermJobsManage)
	require.True(t, CanAccessSurface(jobsPS, "settings.category.jobschedule", "env-a"))
	require.True(t, CanAccessSurface(jobsPS, "landing.settings", "env-a"))
	require.False(t, CanAccessSurface(jobsPS, "settings.category.jobschedule", "env-b"))

	customizePS := NewPermissionSet()
	customizePS.AddGlobal(PermCustomizeManage)
	require.True(t, CanAccessSurface(customizePS, "customize.category.registries", "env-a"))
	require.True(t, CanAccessSurface(customizePS, "landing.customize", "env-a"))

	require.False(t, CanAccessSurface(NewPermissionSet(), "missing.surface", "env-a"))
}

func TestAccessSurfaceRegistryIsDefensiveAndInternallyConsistent(t *testing.T) {
	surfaces := AccessSurfaces()
	require.NotEmpty(t, surfaces)

	surfaces[0].Permissions = append(surfaces[0].Permissions, "unknown:permission")
	surfaces[0].Children = append(surfaces[0].Children, "missing.child")

	fresh := AccessSurfaces()
	require.NotContains(t, fresh[0].Permissions, "unknown:permission")
	require.NotContains(t, fresh[0].Children, "missing.child")

	for _, surface := range fresh {
		for _, perm := range surface.Permissions {
			require.True(t, IsKnownPermission(perm), "surface %s references unknown permission %s", surface.ID, perm)
		}
		for _, childID := range surface.Children {
			_, ok := AccessSurfaceByID(childID)
			require.True(t, ok, "surface %s references unknown child %s", surface.ID, childID)
		}
	}
}

func requireAccessSurfaceInternal(t *testing.T, id string) AccessSurface {
	t.Helper()

	surface, ok := AccessSurfaceByID(id)
	require.True(t, ok, "expected access surface %s to exist", id)

	return surface
}
