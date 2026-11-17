# Arch Linux package

Kalo uses the same BlueZ, obexd and D-Bus backend on Arch Linux as it does on
Ubuntu. The `PKGBUILD` builds the current `main` branch as `kalo-git`; the
desktop entry, icon and manual page are shared with the Ubuntu package from
`packaging/common/`.

## Build and install

Install the usual Arch build tools first (they are part of `base-devel`):

```sh
sudo pacman -S --needed base-devel git rust cargo
```

Then build the package from this directory:

```sh
cd packaging/arch
makepkg -si
```

`makepkg` installs the declared runtime dependencies: BlueZ, obexd and the
X11/Wayland libraries used by iced. Install `vulkan-icd-loader` and a working
GPU driver for hardware rendering, and an XDG desktop portal backend for the
native file picker:

```sh
sudo pacman -S --needed vulkan-icd-loader xdg-desktop-portal-gtk
```

Run Kalo from the application menu or with:

```sh
kalo
```

Remove the package with `sudo pacman -Rns kalo-git`.

## AUR

The package is AUR-ready (`.SRCINFO` is checked in) but has not been published
to the AUR yet. Until then, build it from a checkout as described above.
