# Ubuntu package

Build a real `.deb` without installing `debhelper` or `cargo-deb`:

```sh
./packaging/ubuntu/build-deb.sh
```

The package is written to `dist/kalo_<version>-1_<arch>.deb`. Install it with:

```sh
sudo apt install ./dist/kalo_0.1.0-1_amd64.deb
```

Remove it with `sudo apt remove kalo`.

## Runtime

Receiving and sending need BlueZ and obexd:

```sh
sudo apt install bluez bluez-obexd
```

The file picker uses the XDG desktop portal, which is installed by default on
Ubuntu desktop. Kalo itself talks to the session bus (`org.bluez.obex`) and the
system bus (`org.bluez`), so no background service needs to be enabled.

## Notes

- The package is `Architecture: <native>` (`amd64` here). Build inside the
  oldest Ubuntu release you need if the `.deb` must run on older systems,
  because the binary links against that release's glibc.
- `DEB_ARCH=arm64` can override the architecture when cross-packaging an
  already-built binary, but the binary itself must match.
- `DEB_MAINTAINER="Name <mail>" ./packaging/ubuntu/build-deb.sh` overrides the
  maintainer field (defaults to the local git author).
