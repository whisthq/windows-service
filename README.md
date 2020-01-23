# Fractal Windows System Service

This repository contains the code for the Fractal Service which is installed on every Fractal cloud computer and runs at startup to log the computer into the console session (session 0) with Admin privileges, disable the Windows lock screen and start/monitor the Fractal protocol executable, starting/restarting it if necessary so that it is always running.

This code is all in Visual C# and requires Visual Studio with the .NET Framework 4.7+ for building. Simply build the service by clicking on "Build" in Visual Studio after opening the .sln file.

The service then needs to be installed. Navigate to the .exe directory, which should be under `fractal-service/FractalService/FractalService/bin/Debug` and install it by running `installutil FractalService.exe`.

If it fails, you need to set permission in the Windows registry. Open the registry by typing `regedit.exe` in the search bar, navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog`, right-click `EventLog` and select `Permissions`. Then check `Full Access` for the authenticated users, spin up a new terminal and run the install again. It should now install correctly.

You can then go to the Services application on Windows, locate the process and start it by pressing Start. It should run as SYSTEM under the Details tab. You can stop it there as well. Before making any modifications to the code, the service needs to be uninstalled with `installutil /u FractalService.exe`. You can open `Events Viewer`, click on `Applications and Services Logs` and click on `FractalLog` to see the logs from this service, which is the best way to debug the service.

The /bin/Debug folder contains the pre-compiled executable for a VM. You can simply download it, install it with `installutil FractalService.exe` and it should be good to start automatically at boot.
