# Generate tar.gz for cluster upgrade

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  

    
## Overview

By default, tar.gz is not generated while doing cluster upgrade(--upgrade) using acc-provision. A new argument(-z) is introduced to generate tar.gz while doing cluster upgrade.


## Mechanism

When `-z <filename.tar.gz>` is passed as an argument to acc-provision along with `--upgrade` option, <filename>.tar.gz will be generated which contains ACI CNI operator yamls.

Run `acc-provision --upgrade` command with `-z <filename>` option
```sh
acc-provision --upgrade -c <input.yaml> -f <flavor> -u <uname> -p <pwd> -o <upgrade_deployment.yaml> -z <upgrade_deployment.tar.gz>
```
