# Fractal Windows Service

![Windows Service CI](https://github.com/fractalcomputers/windows-service/workflows/Windows%20Service%20CI/badge.svg)

This repository contains the code for the Fractal Windows service, which is installed on every Fractal Windows VM/container and runs at startup to log the computer into the console session, session 0, with Admin privileges and start/monitor the Fractal protocol, starting/restarting it as necessary to keep it running 24/7. The service also sets high priority to the Fractal Protocol process, which ensures it does not get crowded out when a computer's resources are maximally utilized.

For further documentation, check this repository's [Wiki](https://github.com/fractalcomputers/windows-service/wiki). 

## Building

This project is implemented in Visual C# and requires Visual Studio with the .NET Framework 4.7+ for building. To build the code, you simply need to open the `.sln` file in Visual Studio, and then click "Build" in the top bar (Build Tab, and then Build should be the first option).

Once the executable is built, it needs to be installed via `installutil` (see below) to be run as a Windows Service. On a non-dev VM/container, another service installer needs to be used as installutil is part of the .NET Visual Studio framework, which we do not install on production VMs/containers. You can find the service installer used in production in the `fractalcomputers/setup-scripts` repository, it is called `sc.exe`. For developing the service, you should stick with `installutil` as it makes it easier to install and uninstall frequently.

## Development

All the code written for the service is in the file `FractalService.cs`. This is where all the functions related directly to the Fractal service are written, while the other files are helper files for writting services on Windows and were prepopulated by the project template. There is a function to start the service, `OnStart()`, one to stop it, `OnStop()`, one to monitor it and restart it if it crashes/exists, `MonitorProcess()`, and one to launch the Fractal Protocol as a console process, `LaunchConsoleProcess()`, which is where most of work lives. If you need to modify the service, `LaunchConsoleProcess` is likely the function you will need to modify.

The service needs to be installed before it can be used, both for production and development. Navigate to the `.exe` directory, which should be under `windows-service/FractalService/bin/Debug`, if you've just built it, and install it by running `installutil FractalService.exe`. You should develop by building to `Debug` mode, and build to `Release` mode when you are ready to publish. You **need** to run this installation command from an Administrator command prompt, typically x86_64 Cross Tools Command Prompt for VS 2019, otherwise it will fail with error `The source was not found, but some or all event logs could not be searched. Inaccessible logs: Security, State`.

If it fails, you need to set proper permissions in the Windows registry. Open the registry by typing `regedit.exe` in the Windows search bar, navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog`, right-click `EventLog` and select `Permissions`. Then, check `Full Access` for the authenticated users, spin up a new terminal and run the install command again. It should now install properly.

You can then go to the `Services` application on Windows, locate the `FractalService` process and start it by pressing Start. It should run as `SYSTEM` under the Details tab. You can stop it from there as well. Before making any modifications to the code, the service needs to be stopped manually from the `Services` application and then uninstalled by running `installutil /u FractalService.exe`. 

To view the logs of the service, you can open the `Events Viewer` application, click on `Applications and Services Logs`, and click on `FractalLog`, which is the best way to debug it as you can't see any regular print statement with a service. The typical development workflow is:

- Uninstall the service
- Make your modifications and add plentry of event logs
- Rebuild the service
- Reinstall the service and restart it
- Check the Event Viewer application to see the logs and the behavior of the program

Rinse and repeat until the service works the way you intend it to! Note that your work should be PR-ed to `dev` and pass the GitHub Actions tests before being merged.

## Publishing

Every push to `master` will automatically publish the new service, built with the `Release` tag, to AWS S3 and notify the team in Slack. The Windows service will then be automatically updated the next time a server update is pushed for the Fractal Protocol servers.
