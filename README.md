# Gitea Interceptor

```bash
podman machine init
podman machine start
LOCAL_REGISTRY=$(yq e ".local-registry" ${OKD_LAB_PATH}/lab-config/dev-cluster.yaml)
podman login -u openshift-mirror ${LOCAL_REGISTRY}
cp ~/.config/containers/auth.json ~/.docker/config.json

export KO_DOCKER_REPO=${LOCAL_REGISTRY}/tekton

mkdir -p out
go clean -modcache
go mod tidy
ko resolve --platform=linux/amd64 --preserve-import-paths -t latest -f ./config > ./out/interceptors.yaml
```
