# kelfdump
PS2 homebrew to dump decrypted KELFs using the MechaCon

## Building
You need the [ps2dev toolchain](https://github.com/ps2dev/ps2dev)

If you have ps2dev installed to `/usr/local/ps2dev`, you can run `source setup-env.sh` to automatically setup all environment variables.

Once setup, simply run

```bash
make
```

## Usage
Run using a loader such as [wLaunchELF](https://github.com/ps2homebrew/wLaunchELF). Files will be dumped to the `KELFDUMP` directory on your USB drive.

### Notes

* Only tested on my own hardware, would appreciate feedback from others :)

### TODO
* Maybe add a nice background picture :)
