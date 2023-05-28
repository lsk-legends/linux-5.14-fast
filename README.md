# Rapidswap Kernel

## Prerequisites
Hardware:
* Mellanox ConnectX-3/4 (Infiniband)

Software:
* OS: Ubuntu 20.04 
* gcc 9.4

Driver:
We use the RDMA driver in kernel directly so no MLNX OFED driver is needed.
There is a `config-with-rdma-driver in the root directory of the kernel repo which works on our machines. Basically I enabled the following options related to INFINIBAND and MLX4 here:

```txt
CONFIG_INFINIBAND=y
CONFIG_INFINIBAND_USER_MAD=y
CONFIG_INFINIBAND_USER_ACCESS=y
CONFIG_INFINIBAND_USER_MEM=y
CONFIG_INFINIBAND_ON_DEMAND_PAGING=y
CONFIG_INFINIBAND_ADDR_TRANS=y
CONFIG_INFINIBAND_VIRT_DMA=y
CONFIG_INFINIBAND_MTHCA=y
# CONFIG_INFINIBAND_MTHCA_DEBUG is not set
CONFIG_INFINIBAND_QIB=y
CONFIG_INFINIBAND_CXGB4=m
# CONFIG_INFINIBAND_EFA is not set
CONFIG_MLX4_INFINIBAND=y

# ...

CONFIG_NET_VENDOR_MELLANOX=y
CONFIG_MLX4_EN=y
CONFIG_MLX4_EN_DCB=y
CONFIG_MLX4_CORE=y
CONFIG_MLX4_DEBUG=y
CONFIG_MLX4_CORE_GEN2=y
```

## Build
We use the `build_kernel.sh` script to build and install kernel.
Here are the instructions:
1. copy the `config-5.14` to `.config`. Modify it if needed.
2. `build_kernel.sh build` to build the kernel image and modules.
3. `build_kernel.sh install` to install both the kernel image and all kernel modules. `build_kernel.sh replace` will replace the kernel image but leave kernel modules unchanged.
4. Check the grub file at `/etc/default/grub`, select the default kernel, add boot options, etc.
5. Update grub with `sudo update-grub` on Ubuntu.
6. Reboot the machine and enter with newly compiled kernel.

## Necessary softwares
install ofed driver with version **MLNX_OFED_LINUX-5.6-2.0.9.0-ubuntu20.04-x86_64**

After the installation we should be able to use `ibstat` and utils like `ib_[read|write]_[lat|bw]`.

And we can configure IPs for the Infiniband devices now. Either `ifconfig` or `netplan` should work.

## Install remoteswap kernel module
Refer the README in the remoteswap repo for the instructions.
For now only the `5.14-batch-store` branch in the remoteswap repo works with this particular branch.
Note that because of our dirty hack in the kernel, the kernel probably **cannot** swap to disks even when the remoteswap module is not installed.


## Run applications
We use cgroup-v1 to limit the memory an application can use. Fastswap requires cgroup-v2 which provide the `memory.high` interface for them to trigger the reclamation offloading. In our ported version, we dirty hacked and set the `memory.high` counter along with `memory.limit_in_bytes` with a specified headroom. Anyway, cgroup-v1 should be functional enough in our experiments.

I usually use cgexec and taskset to set the memory cgroup and what CPU cores the application will have:
```bash
mkdir /sys/fs/cgroup/memory/<cgroup name>
echo <limit size, e.g., 2560m> > /sys/fs/cgroup/memory/<cgroup name>/memory.limit_in_bytes
cgexec --sticky -g memory:<cgroup name> taskset -c <cores> /usr/bin/time -v <command>
```
