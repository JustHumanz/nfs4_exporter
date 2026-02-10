#!/bin/bash
set -e

IMAGE_NAME="nfs4-exporter"
TAG="${1:-latest}"

echo "Building Docker image: ${IMAGE_NAME}:${TAG}"

docker build -t ${IMAGE_NAME}:${TAG} .

echo ""
echo "Build complete! To run the container:"
echo ""
echo "  docker run --rm --privileged \\"
echo "    --pid=host \\"
echo "    --network=host \\"
echo "    -v /sys/kernel/debug:/sys/kernel/debug:ro \\"
echo "    ${IMAGE_NAME}:${TAG}"
echo ""
echo "Note: The container requires:"
echo "  - --privileged: To load eBPF programs"
echo "  - --pid=host: To access host kernel"
echo "  - --network=host: For easy metrics access on localhost:2112"
echo "  - /sys/kernel/debug volume: For kernel debugging interface"
