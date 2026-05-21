package enforcer

import "time"

// ContainerInfo holds identity fields from the start event, preserved for reporting at detach time.
type ContainerInfo struct {
	ContainerID      string
	ProjectPath      string
	JobID            string
	PipelineID       string
	JobURL           string
	GitRef           string
	JobName          string
	JobStage         string
	PipelineSrc      string
	CgroupPath       string // pre-resolved cgroup path (containerd), empty = resolve from PID
	Action           string // policy action at attach time
	AllowProcMemRead bool   // leitwacht.io/allow-proc-read=true label exemption
	AllowCredWatch   bool   // leitwacht.io/allow-cred-read=true label exemption
	StartedAt        time.Time
}

// DetachResult holds everything collected when enforcement ends.
type DetachResult struct {
	Info  ContainerInfo
	Stats EgressStats
}
