# SYMFIT Kernel - Run Directory

This README provides instructions for building the Docker image, compiling the kernel, and running the scripts in this directory.

## 1. Building the Docker Image

To build the Docker image using the provided `Dockerfile`, run the following command from this directory:

```sh
docker build -t system-mode-sym .
```

This will create a Docker image named `system-mode-sym` with all necessary dependencies.

---

## 2. Launching the Docker Environment

To start a container with the built image and the required volume mappings, use the `launch.sh` script from this directory:

```sh
./launch.sh
```

This script mounts the main directory and the challenge source directory into the container, installs some programs, and opens an interactive shell.

---

## 3. Compiling the Kernel

Inside the Docker container, run the `compile.sh` script to build the kernel:

- To configure and build:
  ```sh
  ./compile.sh config
  ```
- To build only (if already configured):
  ```sh
  ./compile.sh
  ```

---

## 4. Running the Kernel in QEMU

Use the `run_vng.sh` script to launch the built kernel in QEMU with the appropriate options(again from this directory):

```sh
./run_vng.sh
```

This script will start QEMU with the built kernel image (`bzImage`) and the required arguments for your environment.

the provided kernel image is built from https://github.com/aixcc-public/challenge-001-exemplar

---

## 6. Running a Test File and Viewing Output

This repo includes a test file called `kernel_syscall_test` and a input for this file `sockopt_input.bin`
After launching the VM, navigate to `./workdir/` where you will find these files, then run `./kernel_syscall_test sockopt_input.bin`
The symbolic mode will then start. The system might lock up, so you need to open another terminal to view the generated files.
In another terminal, run `docker ps` to get the container ID, then run `docker exec -it <container ID> /bin/bash` to mount to the running container with another shell.
In the main directory you will see a new folder `./output` which contains all of the temporary files (such as new branch finding inputs). Use a program like xxd to view these files.
If the system locks up, you can stop the run by running `docker stop <container ID>` in the second terminal. The first terminal should then unfreeze and be ready for future use. 

---

## 7. Running a JSON script using the syscall interpreter

This repo includes an interpreter to dynamically run syscalls, including the option to stick them in symbolic memory for the solver to manipulate. This will automatically be compiled from
source as the docker image is run. To run the test application from /workdir: ./claude_syscall5c <input file> <options>. Options include --cleanup to unallocate any hanging file descriptors, 
pipes or mmaped memory regions. Additionally, --symbolic-mem <address> may be specified to instruct the interpreter on which addresses to load and dereference integer arguments from when in
symbolic mode. Adding --file <filename> will make the interpreter open a file descriptor for use by syscalls for a specific file. Upon termination of the interpreter, the file descriptor will
automatically be closed.

A number of test scripts have been included in JSON format. printq3.json is currently the recommended demonstration script to use. $file may be used to specify the descriptor derived from
opening a file name via the aforementioned --file argument. As well, return values are stored and can be referenced later. For example, to reference the return value from the first syscall run,
use $0. To reference the second return value, use $1, and so on. Other than this, this general format should be observed when changing or adding syscalls to scripts:

[
  {"syscall": <syscall number>, "args": <comma separated arguments; maximum of six>, "symbolic": <true/false>}, <-- Always put a comma at the end to denote more syscalls for the system to parse
]

For example:

[
  {"syscall": 2, "args": ["/workdir/data.txt", 0], "symbolic": true},
  {"syscall": 9, "args": [0x10000000, 1024, 3, 50, -1, 0], "symbolic": true}
]

## 8. Files in this Directory

- `Dockerfile`: Docker build instructions for the required environment.
- `launch.sh`: Script to launch the Docker container with correct mounts.
- `compile.sh`: Script to configure and build the kernel.
- `run_vng.sh`: Script to run the kernel in QEMU.
- `bzImage`: The provided kernel image.

---

## Notes
- Ensure Docker is installed and running on your system before building the image.
- Adjust relative paths as needed for your local setup.
- For advanced usage or troubleshooting, refer to comments inside each script.
