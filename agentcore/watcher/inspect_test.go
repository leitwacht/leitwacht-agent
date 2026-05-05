package watcher

import (
	"testing"
)

func TestExtractContainerEvent_BuildContainer(t *testing.T) {
	labels := map[string]string{
		"com.gitlab.gitlab-runner.managed":     "true",
		"com.gitlab.gitlab-runner.job.id":      "123",
		"com.gitlab.gitlab-runner.pipeline.id": "456",
		"com.gitlab.gitlab-runner.job.url":     "https://gitlab.example.com/team/app/-/jobs/123",
		"com.gitlab.gitlab-runner.job.ref":     "main",
	}
	env := []string{
		"CI_PROJECT_PATH=team/app",
		"CI_JOB_NAME=build",
		"CI_JOB_STAGE=build",
		"CI_PIPELINE_SOURCE=push",
		"FF_NETWORK_PER_BUILD=true",
		"HOME=/root",
	}

	ev := extractContainerEvent("start", "abc123full", labels, env, nil, "runc", 42, "", Scope{})
	if ev == nil {
		t.Fatal("expected event for build container")
	}
	if ev.ProjectPath != "team/app" {
		t.Fatalf("project = %q", ev.ProjectPath)
	}
	if ev.JobID != "123" {
		t.Fatalf("job_id = %q", ev.JobID)
	}
	if ev.JobName != "build" {
		t.Fatalf("job_name = %q, want %q", ev.JobName, "build")
	}
	if ev.JobStage != "build" {
		t.Fatalf("job_stage = %q, want %q", ev.JobStage, "build")
	}
	if ev.PipelineSrc != "push" {
		t.Fatalf("pipeline_src = %q, want %q", ev.PipelineSrc, "push")
	}
	if ev.HasDinD || ev.HasSocketMount || ev.HasGVisor || ev.MissingNetworkPerBld {
		t.Fatalf("unexpected flags: dind=%v socket=%v gvisor=%v ff=%v",
			ev.HasDinD, ev.HasSocketMount, ev.HasGVisor, ev.MissingNetworkPerBld)
	}
}

func TestExtractContainerEvent_EnvVarFallback(t *testing.T) {
	// No Docker labels — simulates containerd/K8S where GitLab labels don't exist.
	labels := map[string]string{}
	env := []string{
		"CI_PROJECT_PATH=team/app",
		"CI_JOB_ID=789",
		"CI_PIPELINE_ID=101",
		"CI_JOB_URL=https://gitlab.example.com/team/app/-/jobs/789",
		"CI_COMMIT_REF_NAME=feature-branch",
		"CI_JOB_NAME=build-image",
		"CI_JOB_STAGE=build",
		"CI_PIPELINE_SOURCE=merge_request_event",
		"FF_NETWORK_PER_BUILD=true",
	}

	ev := extractContainerEvent("start", "ctrd-abc123", labels, env, nil, "runc", 99, "", Scope{})
	if ev == nil {
		t.Fatal("expected event for containerd build container")
	}
	if ev.JobID != "789" {
		t.Fatalf("JobID = %q, want %q", ev.JobID, "789")
	}
	if ev.PipelineID != "101" {
		t.Fatalf("PipelineID = %q, want %q", ev.PipelineID, "101")
	}
	if ev.JobURL != "https://gitlab.example.com/team/app/-/jobs/789" {
		t.Fatalf("JobURL = %q", ev.JobURL)
	}
	if ev.GitRef != "feature-branch" {
		t.Fatalf("GitRef = %q, want %q", ev.GitRef, "feature-branch")
	}
	if ev.JobName != "build-image" {
		t.Fatalf("JobName = %q, want %q", ev.JobName, "build-image")
	}
}

func TestExtractContainerEvent_LabelsOverrideEnv(t *testing.T) {
	// When both labels and env exist, labels take precedence (Docker path).
	labels := map[string]string{
		"com.gitlab.gitlab-runner.managed": "true",
		"com.gitlab.gitlab-runner.job.id":  "123",
	}
	env := []string{
		"CI_PROJECT_PATH=team/app",
		"CI_JOB_ID=999",
		"FF_NETWORK_PER_BUILD=true",
	}

	ev := extractContainerEvent("start", "abc123", labels, env, nil, "runc", 42, "", Scope{})
	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.JobID != "123" {
		t.Fatalf("JobID = %q, want %q (label should win)", ev.JobID, "123")
	}
}

func TestExtractContainerEvent_MissingCIJobName(t *testing.T) {
	labels := map[string]string{"com.gitlab.gitlab-runner.managed": "true"}
	env := []string{
		"CI_PROJECT_PATH=team/app",
		"FF_NETWORK_PER_BUILD=true",
	}

	ev := extractContainerEvent("start", "abc123full", labels, env, nil, "runc", 42, "", Scope{})
	if ev == nil {
		t.Fatal("expected event for build container")
	}
	if ev.JobName != "" {
		t.Fatalf("job_name = %q, want empty", ev.JobName)
	}
	if ev.JobStage != "" {
		t.Fatalf("job_stage = %q, want empty", ev.JobStage)
	}
	if ev.PipelineSrc != "" {
		t.Fatalf("pipeline_src = %q, want empty", ev.PipelineSrc)
	}
}

func TestExtractContainerEvent_HelperContainer(t *testing.T) {
	labels := map[string]string{"com.gitlab.gitlab-runner.managed": "true"}
	env := []string{"HOME=/root"} // no CI_PROJECT_PATH

	ev := extractContainerEvent("start", "abc123full", labels, env, nil, "runc", 42, "", Scope{})
	if ev != nil {
		t.Fatal("expected nil for helper container")
	}
}

func TestExtractContainerEvent_DinD(t *testing.T) {
	labels := map[string]string{"com.gitlab.gitlab-runner.managed": "true"}
	env := []string{
		"CI_PROJECT_PATH=team/app",
		"DOCKER_HOST=tcp://docker:2375",
		"FF_NETWORK_PER_BUILD=true",
	}

	ev := extractContainerEvent("start", "abc123full", labels, env, nil, "runc", 42, "", Scope{})
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if !ev.HasDinD {
		t.Fatal("expected DinD detection")
	}
}

func TestExtractContainerEvent_SocketMount(t *testing.T) {
	labels := map[string]string{"com.gitlab.gitlab-runner.managed": "true"}
	env := []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=true"}
	mounts := []string{"/var/run/docker.sock"}

	ev := extractContainerEvent("start", "abc123full", labels, env, mounts, "runc", 42, "", Scope{})
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if !ev.HasSocketMount {
		t.Fatal("expected socket mount detection")
	}
}

func TestExtractContainerEvent_GVisor(t *testing.T) {
	labels := map[string]string{"com.gitlab.gitlab-runner.managed": "true"}
	env := []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=true"}

	ev := extractContainerEvent("start", "abc123full", labels, env, nil, "runsc", 42, "", Scope{})
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if !ev.HasGVisor {
		t.Fatal("expected gVisor detection")
	}
}

func TestExtractContainerEvent_MissingFFNetworkPerBuild(t *testing.T) {
	labels := map[string]string{"com.gitlab.gitlab-runner.managed": "true"}

	tests := []struct {
		name string
		env  []string
		want bool
	}{
		{"missing", []string{"CI_PROJECT_PATH=team/app"}, true},
		{"false", []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=false"}, true},
		{"zero", []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=0"}, true},
		{"true", []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=true"}, false},
		{"one", []string{"CI_PROJECT_PATH=team/app", "FF_NETWORK_PER_BUILD=1"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := extractContainerEvent("start", "abc", labels, tt.env, nil, "runc", 42, "", Scope{})
			if ev.MissingNetworkPerBld != tt.want {
				t.Fatalf("MissingNetworkPerBld = %v, want %v", ev.MissingNetworkPerBld, tt.want)
			}
		})
	}
}
