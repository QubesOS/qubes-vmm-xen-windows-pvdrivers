# Xen Windows PV drivers used for Windows guests in Qubes OS.

Contains libxenvchan implementtion for Windows.

TODO: integrate with Qubes builder

`EWDK_PATH` env variable must be set to the root of MS Enterprise WDK for Windows 10/Visual Studio 2022.
PV drivers are built by a dummy project in the solution (`pvdrivers`).

`build.cmd` script builds the solution from command line using the EWDK (no need for external VS installation).
Usage: `build.cmd Release|Debug [sign]`

PV drivers are not signed unless the `sign` parameter is used (then test signed).
