# Acquisition bundle v1 fixtures

`valid/` is an entirely synthetic, hardware-free bundle containing firmware
images, a passive capture, a transaction log, and a collector log. It also
records honest missing, modified, encrypted, virtual-read, and calibration-only
artifact states.

Each directory under `negative/` contains a schema-valid manifest whose
filesystem state contradicts one declared property. Tests assert stable issue
codes instead of depending only on prose error messages.
