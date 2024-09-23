# Cross Compiling ACI-CNI for ARM

This guide walks you through cross-compiling the ACI-CNI plugin for ARM64 architecture, including preparing your environment, and building both binaries and container images for the ARM platform.

## Table of Contents

- [Overview of building ACI-CNI for ARM64](#overview-of-building-aci-cni-for-arm64)
    - [Prepare the Environment](#prepare-the-enviorment)
    - [Build Process Overview](#build-process-overview)
- [Instructions on building containers on `Ubuntu 22.04`](#instructions-on-building-containers-on-ubuntu-2204)
    - [Define Container Image Registry and Tag](#define-container-image-registry-and-tag)
    - [Build ARM-specific Opflex](#build-arm-specific-opflex)
    - [Compile ACI Containers Binaries](#compile-aci-containers-binaries)
    - [Build ARM-specific Openvswitch](#build-arm-specific-openvswitch)
    - [Build ARM-specific ACI-CNI Container Images](#build-arm-specific-aci-cni-container-images)
    - [Build ARM-specific `acc-provision-operator` Container Image](#build-arm-specific-acc-provision-operator-container-image)
    - [Verify all Container Images](#verify-all-container-images)


## Overview of building ACI-CNI for ARM64

### Prepare the enviorment:

We are using an `Ubuntu 22.04` machine tro build these container images. Before we can build them the following prerequisites must be met.

1. **Cross-Compiling with CGo:**

    We will need to use a cross-compiler like musl-gcc to handle this. Ensure the correct ARM64-compatible gcc is available, and set the CC variable to point to it.

    Example steps on Ubuntu 22.04:
    ```
    # Download musl-gcc for ARM64 architecture to ~/downloads
    wget -P ~/downloads https://musl.cc/aarch64-linux-musl-cross.tgz

    # Create a directory for the musl toolchain in /opt/musl-cross
    mkdir -p /opt/musl-cross

    # Extract the tarball to the newly created directory
    tar -xvf ~/downloads/aarch64-linux-musl-cross.tgz -C /opt/musl-cross
    ```

2. **Docker `buildx`:**

    Docker `buildx` plugin is required to build multiplatform containers. Please look at the instructions to install buildx at https://github.com/docker/buildx?tab=readme-ov-file#linux-packages
    > Docker version 19.03 or higher is required to utilize `buildx`
    - Allow multiarch images to be build in your env:
    ```
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    ```
    - Check if arm is supported:
    ```
    $ docker buildx ls
    NAME/NODE     DRIVER/ENDPOINT   STATUS    BUILDKIT         PLATFORMS
    default*      docker                                       
    \_ default    \_ default       running   v0.8.2+eeb7b65   linux/amd64, linux/386, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/arm/v7, linux/arm/v6
    ```

### Build Process Overview: 

1. **Update Makefile:**

    To compile Go code for different architectures (e.g., ARM64), we update the `all-static` make target in the `aci-containers` repo to include the following flags:
    ```
    GOARCH=arm64 CC=/opt/musl-cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
    ```

    **Cross compile the aci-containers binaries:**

    After updating the makefile for aci-containers repo, we can cross-compile as follows
    ```
    make all-static
    ```

2. **Update Dockerfiles:**

    If a Dockerfile has a references to x86_64 libraries, we will replace them with similar repos for arm64 in both aci-containers repo and the opflex repo.
    In the aci-containers and opflex repos please update the Dockerfiles under `docker/travis/` directory.
    > Typically replacing x86_64 with aarch64 should work but please check if a similar package exists.

    | x86_64                                               | arm64/aarch64                                               |
    |------------------------------------------------------ | :-------------------------------------------------------------: |
    | https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os | https://mirror.stream.centos.org/9-stream/BaseOS/aarch64/os |
    | https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os | https://mirror.stream.centos.org/9-stream/AppStream/aarch64/os |
    | https://mirror.stream.centos.org/9-stream/CRB/x86_64/os | https://mirror.stream.centos.org/9-stream/CRB/aarch64/os |
    | https://mirror.stream.centos.org/9-stream/AppStream/x86_64/debug/tree | https://mirror.stream.centos.org/9-stream/AppStream/aarch64/debug/tree |
    | codeready-builder-for-rhel-8-x86_64-rpms             | codeready-builder-for-rhel-8-aarch64-rpms                   |
    | kernel-headers-4.18.0-147.8.1.el8_1.x86_64           | kernel-headers-4.18.0-147.8.1.el8_1.aarch64.rpm             |
    | kernel-devel-4.18.0-147.8.1.el8_1.x86_64             | kernel-devel-4.18.0-147.8.1.el8_1.aarch64.rpm               |
    | kernel-modules-4.18.0-147.8.1.el8_1.x86_64           | kernel-modules-4.18.0-147.8.1.el8_1.aarch64.rpm             |
    
    **Cross build with docker buildx:**

    Once the Dockerfiles have been updated they can be built as follows:
    ```
    docker buildx build --no-cache --platform linux/arm64 -t ${IMAGE_BUILD_REGISTRY}/<image>:${IMAGE_BUILD_TAG} --file=docker/travis/Dockerfile-<target> .
    ```

While the above steps explain the process to empower a user to build arm64 images themselves, the below step-by-step instructions can be followed to ensure a build on an `Ubuntu 22.04` machine.

##  Instructions on building containers on `Ubuntu 22.04`

###  Define Container Image Registry and Tag:
    
We will first define the image build registry and image tag, this will build all container images as
`$IMAGE_BUILD_REGISTRY/<Image_Name>:IMAGE_BUILD_TAG`
    
    ```
    export IMAGE_BUILD_REGISTRY="my_registry"
    export IMAGE_BUILD_TAG="v0.1-test"
    ```
Please replace "my_registry" and "v0.1-test" with the relevant registry name and tag in your environment.

###  Build ARM-specific Opflex:
1. **Clone the Opflex repository:**
   ```
   git clone https://github.com/noironetworks/opflex.git
   cd opflex
   ```
2. **Copy the [arm64 opflex patch](arm64-opflex.patch) to opflex directory**    
3. **Apply the ARM64 build patch:**
    ```
    git apply ./arm64-opflex.patch
    ```
4. **Build Opflex Images:**
    We will build  opflex images with the script `docker/travis/build-opflex-travis.sh`.
    ```
    docker/travis/build-opflex-travis.sh $IMAGE_BUILD_REGISTRY $IMAGE_BUILD_TAG
    ```

    This script can take three parameters:
    1. Image Registry
    2. Image Tag
    3. Build args: We can provide additional build arguments for docker buildx build commands, for example if you are using an http proxy you may use the script as:

        `docker/travis/build-opflex-travis.sh $IMAGE_BUILD_REGISTRY $IMAGE_BUILD_TAG "--build-arg https_proxy=${HTTP_PROXY} --build-arg no_proxy=${NO_PROXY}"`

The above steps will build three containers:
```
1. $IMAGE_BUILD_REGISTRY/opflex-build-base:$IMAGE_BUILD_TAG
2. $IMAGE_BUILD_REGISTRY/opflex-build:$IMAGE_BUILD_TAG
3. $IMAGE_BUILD_REGISTRY/opflex:$IMAGE_BUILD_TAG
```

### Compile ACI Containers binaries:
1. **Clone the ACI-Containers repository:**
   ```
   git clone https://github.com/noironetworks/aci-containers.git
   cd aci-containers
   ```
2. **Copy the [arm64 aci patch](arm64-aci.patch) to aci-containers directory**    
3. **Apply the ARM64 build patch:**
    ```
    git apply ./arm64-aci.patch
    ```
4. **Build ACI Containers binaries**
    ```
    make clean-dist-static all-static
    ``` 
5. **Copy Iptables binaries**

    Once the binaries have been built we need to copy some additional files to the dist-static directory in aci-containers. We will use `docker/copy_iptables.sh` script to copy iptables binaries and libraries from opflex-build-base container built in the earlier step into dist-static to be used by consumers of iptables like the host agent container.
    ```
    ./docker/copy_iptables.sh $IMAGE_BUILD_REGISTRY/opflex-build-base:$IMAGE_BUILD_TAG dist-static
    ```   

### Build ARM-specific OpenvSwitch:
 
We will build OpenvSwitch with the script [openvswitch-arm64.sh](openvswitch-arm64.sh). Copy the script to aci-containers directory and run it. 
 
Script usage:
```
./build_openvswitch.sh  $IMAGE_BUILD_REGISTRY $IMAGE_BUILD_TAG
```
This script can take three parameters:
1. Image Registry
2. Image Tag
3. Build args: We can provide additional build arguments for docker buildx build commands, for example if you are using an http proxy you may use the script as:
`./build_openvswitch.sh $IMAGE_BUILD_REGISTRY $IMAGE_BUILD_TAG "--build-arg https_proxy=${HTTP_PROXY} --build-arg no_proxy=${NO_PROXY}"`

The above steps will build two containers:
```
1. $IMAGE_BUILD_REGISTRY/openvswitch-base:$IMAGE_BUILD_TAG
2. $IMAGE_BUILD_REGISTRY/openvswitch:$IMAGE_BUILD_TAG
```

###  Build ARM-specific ACI-CNI Container Images 
We will use Docker Buildx to create multi-architecture images: 

`docker buildx build --no-cache -t <tag>  --platform linux/arm64 -f Dockerfile --push .`

**Build the Containers:**

```
docker buildx build --no-cache --platform linux/arm64 -t ${IMAGE_BUILD_REGISTRY}/aci-containers-controller:${IMAGE_BUILD_TAG} --file=docker/travis/Dockerfile-controller .
docker buildx build --no-cache --platform linux/arm64 --target without-ovscni -t ${IMAGE_BUILD_REGISTRY}/aci-containers-host:${IMAGE_BUILD_TAG} --file=docker/travis/Dockerfile-host .
docker buildx build --no-cache --platform linux/arm64 -t ${IMAGE_BUILD_REGISTRY}/aci-containers-operator:${IMAGE_BUILD_TAG} --file=docker/travis/Dockerfile-operator .
```

### Build ARM-specific `acc-provision-operator` Container Image:

1. **Clone the acc-provision-operator repository**
```
git clone https://github.com/noironetworks/acc-provision-operator.git
cd acc-provision-operator
```
2. **Build the acc-provision-operator container**
```
 docker buildx  build --platform linux/arm64 -t noiro/acc-provision-operator:v01 --file=Dockerfile .
```

### Verify all Container Images:

Run the following command to check the images:
```
docker images
REPOSITORY                               TAG                       IMAGE ID       CREATED         SIZE
my_registry/acc-provision-operator       v0.1-test                 c18ee7b6504a   2 hours ago     1.38GB
my_registry/aci-containers-operator      v0.1-test                 2bcabc38a7fd   7 hours ago     589MB
my_registry/aci-containers-controller    v0.1-test                 aa8defe53b15   7 hours ago     638MB
my_registry/aci-containers-host          v0.1-test                 1a23ghi55aee   7 hours ago     727MB
my_registry/openvswitch                  v0.1-test                 1365jklef73f   7 hours ago     681MB
my_registry/openvswitch-base             v0.1-test                 8f36vwxf45cf   7 hours ago     1.33GB
my_registry/opflex                       v0.1-test                 b631mno78621   10 hours ago    631MB
my_registry/opflex-build                 v0.1-test                 b2dapqr3e890   13 hours ago    2.03GB
my_registry/opflex-build-base            v0.1-test                 46976a7b063b   17 hours ago    3.98GB
```



