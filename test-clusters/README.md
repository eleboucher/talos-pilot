# Test Clusters

Docker-based Talos clusters for testing talos-pilot features.

## Quick Start

```bash
# Create a cluster with Cilium eBPF + Hubble
./scripts/cluster.sh create cilium-hubble

# Or replace existing cluster with --force
./scripts/cluster.sh create cilium-ebpf --force

# Export kubeconfig
export KUBECONFIG=$(pwd)/output/kubeconfig

# Check what you have
./scripts/cluster.sh status

# Add test workloads (healthy, crashing, pending, etc.)
./scripts/cluster.sh workloads all

# Run talos-pilot against it
cd ../
cargo run --bin talos-pilot-tui

# Clean up when done
./scripts/cluster.sh destroy
```

## Available Profiles

| Profile | CNI | KubeSpan | kube-proxy | Notes |
|---------|-----|----------|------------|-------|
| `flannel` | Flannel | No | Yes | Simplest setup |
| `cilium` | Cilium | No | Yes | Legacy mode |
| `cilium-ebpf` | Cilium | No | No | Modern eBPF mode |
| `cilium-hubble` | Cilium | No | No | With Hubble observability |
| `kubespan` | Flannel | Yes | Yes | WireGuard mesh |
| `cilium-kubespan` | Cilium | Yes | No | Problematic combo (for testing warnings) |

## Test Scenarios

### Testing CNI + KubeSpan Warnings

```bash
# Create the problematic combination
./scripts/cluster.sh create cilium-kubespan

# Run talos-pilot - should show warning in diagnostics
cargo run --bin talos-pilot-tui
# Navigate to Diagnostics (d) and check CNI section
```

### Testing Workload Health

```bash
# Create any cluster profile
./scripts/cluster.sh create cilium-ebpf

# Add various workload states
./scripts/cluster.sh workloads healthy     # Healthy deployments
./scripts/cluster.sh workloads crashloop   # CrashLoopBackOff
./scripts/cluster.sh workloads imagepull   # ImagePullBackOff
./scripts/cluster.sh workloads pending     # Pending (unschedulable)
./scripts/cluster.sh workloads pdb         # With PodDisruptionBudget

# Or create all at once
./scripts/cluster.sh workloads all

# Check what you have
kubectl get pods -A
```

### Testing Hubble Flows

```bash
# Create cluster with Hubble
./scripts/cluster.sh create cilium-hubble

# Access Hubble UI
kubectl port-forward -n kube-system svc/hubble-ui 12000:80

# Or use Hubble CLI
hubble observe --follow
```

### Testing Pre-Operation Health Checks

```bash
# Create cluster
./scripts/cluster.sh create cilium-ebpf

# Add workloads with issues
./scripts/cluster.sh workloads crashloop
./scripts/cluster.sh workloads pdb

# Now test pre-operation checks - should show:
# - Pods in CrashLoopBackOff
# - PDBs that would block drain
```

## Directory Structure

```
test-clusters/
├── README.md           # This file
├── patches/            # Talos machine config patches
│   ├── kubespan.yaml       # Enable KubeSpan
│   ├── cilium-cni.yaml     # Disable default CNI for Cilium
│   ├── cilium-ebpf.yaml    # Cilium eBPF mode (no kube-proxy)
│   └── hubble.yaml         # Hubble config reference
├── scripts/
│   └── cluster.sh      # Main cluster management script
└── output/             # Generated files (gitignored)
    └── kubeconfig      # Cluster kubeconfig
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TALOS_CLUSTER_NAME` | `talos-pilot` | Name of the Docker cluster |
| `TALOS_CONTROLPLANES` | `1` | Number of control plane nodes |
| `TALOS_WORKERS` | `0` | Number of worker nodes |
| `TALOS_VERSION` | `v1.9.0` | Talos version to use |
| `TALOS_PROVISIONER` | `docker` | Provisioner (docker or qemu) |

## Tips

### Run Multiple Clusters

```bash
# Cluster 1: Cilium
TALOS_CLUSTER_NAME=cilium-test ./scripts/cluster.sh create cilium-ebpf

# Cluster 2: Flannel + KubeSpan
TALOS_CLUSTER_NAME=kubespan-test ./scripts/cluster.sh create kubespan

# Switch between them
talosctl config context cilium-test
talosctl config context kubespan-test
```

### 3-Node Control Plane (for etcd quorum testing)

```bash
TALOS_CONTROLPLANES=3 TALOS_WORKERS=2 ./scripts/cluster.sh create cilium-ebpf
```

### Check Cilium Status

```bash
# Cilium CLI (if installed)
cilium status

# Or via kubectl
kubectl -n kube-system exec ds/cilium -- cilium status
```

### Check KubeSpan Peers

```bash
talosctl get kubespanpeerstatus -n 10.5.0.2
```

## Troubleshooting

### Nodes NotReady after Cilium install

Cilium takes a minute to initialize. Check pod status:

```bash
kubectl get pods -n kube-system -l k8s-app=cilium
```

### KubeSpan peers not connecting

Check discovery service:

```bash
talosctl get discoveryservice -n 10.5.0.2
```

### Cluster won't start

Check Docker resources - Talos needs memory:

```bash
docker system df
docker system prune  # Clean up if needed
```
