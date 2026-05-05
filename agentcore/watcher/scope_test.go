package watcher

import "testing"

func TestResolveScope(t *testing.T) {
	tests := []struct {
		name   string
		scope  Scope
		labels map[string]string
		env    map[string]string
		want   string
	}{
		{
			name:   "no scope falls back to CI_PROJECT_PATH",
			scope:  Scope{},
			labels: map[string]string{"leitwacht.eu/scope": "ignored"},
			env:    map[string]string{"CI_PROJECT_PATH": "team/app"},
			want:   "team/app",
		},
		{
			name:   "label match wins over CI_PROJECT_PATH",
			scope:  Scope{Label: "leitwacht.eu/scope"},
			labels: map[string]string{"leitwacht.eu/scope": "trusted"},
			env:    map[string]string{"CI_PROJECT_PATH": "team/app"},
			want:   "trusted",
		},
		{
			name:   "label miss falls through to env",
			scope:  Scope{Label: "leitwacht.eu/scope", Env: "LEITWACHT_SCOPE"},
			labels: map[string]string{},
			env:    map[string]string{"LEITWACHT_SCOPE": "team-a", "CI_PROJECT_PATH": "team/app"},
			want:   "team-a",
		},
		{
			name:   "label and env miss fall through to CI_PROJECT_PATH",
			scope:  Scope{Label: "leitwacht.eu/scope", Env: "LEITWACHT_SCOPE"},
			labels: map[string]string{},
			env:    map[string]string{"CI_PROJECT_PATH": "team/app"},
			want:   "team/app",
		},
		{
			name:   "everything empty returns empty (helper container)",
			scope:  Scope{Label: "leitwacht.eu/scope"},
			labels: map[string]string{},
			env:    map[string]string{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveScope(tt.scope, tt.labels, tt.env)
			if got != tt.want {
				t.Errorf("resolveScope = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractContainerEvent_ScopeLabel(t *testing.T) {
	labels := map[string]string{
		"leitwacht.eu/scope":               "trusted-scope",
		"com.gitlab.gitlab-runner.managed": "true",
	}
	env := []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=true"}

	ev := extractContainerEvent("start", "abc123", labels, env, nil, "runc", 42, "",
		Scope{Label: "leitwacht.eu/scope"})

	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.ProjectPath != "trusted-scope" {
		t.Errorf("ProjectPath = %q, want %q (scope label should win)",
			ev.ProjectPath, "trusted-scope")
	}
}
