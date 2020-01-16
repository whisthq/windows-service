# Fractal Windows System Service





if using `installutil FractalService.exe` fails, you need to set permission in the registry

open the registry by typing "regedit.exe", navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog`

right-click `EventLog` and select `Permissions`. Then check `Full Access` for the authenticated users






Fractal's service which runs on the cloud computers and launches console session when a user connects.
