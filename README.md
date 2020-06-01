# Fractal Windows Service

This repository contains the code for the Fractal Service which is installed on every Fractal Windows cloud computer and runs at startup to log the computer into the console session (session 0) with Admin privileges, disable the Windows lock screen and start/monitor the Fractal protocol executable, starting/restarting it if necessary so that it is always running.

## Building

This code is all in Visual C# and requires Visual Studio with the .NET Framework 4.7+ for building. Simply build the service by clicking on "Build" in Visual Studio after opening the `.sln` file. On a non-dev VM, another service installer should be used as installutil is part of the .NET Visual Studio framework, which we do not want to install on production VMs. You can find the service installer used in the `fractalcomputers/setup-scripts` repository.

## Development

The service then needs to be installed before it can be used, either as production or for development. Navigate to the `.exe` directory, which should be under `vm-service/FractalService/FractalService/bin/Debug` and install it by running `installutil FractalService.exe`.

If it fails, you need to set proper permissions in the Windows registry. Open the registry by typing `regedit.exe` in the search bar, navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog`, right-click `EventLog` and select `Permissions`. Then, check `Full Access` for the authenticated users, spin up a new terminal and run the install again. It should now install correctly.

You can then go to the `Services` application on Windows, locate the process and start it by pressing Start. It should run as `SYSTEM` under the Details tab. You can stop it from there as well. Before making any modifications to the code, the service needs to be stopped and uninstalled, with `installutil /u FractalService.exe`. You can open `Events Viewer`, click on `Applications and Services Logs` and click on `FractalLog` to see the logs from this service, which is the best way to debug the service.

## Publishing

You can publish the new service to production, which is hosted on AWS S3, by running `./update.sh`. This script will upload the new service executable to AWS S3 and notify the team in Slack.

If you get permission denied, or if this is your first time doing this for Fractal, you need to download the AWS CLI for your local platform. Your first need to install the CLI via your local package manager, i.e. `brew install awscli`, and then configure it via `aws configure`. This will prompt you for an AWS Acces Key ID and Secret Key ID. You can find those [here](https://console.aws.amazon.com/iam/home?region=us-east-1#/users/UpdateServer?section=security_credentials). You will need to create a new AWS Key and Secret Key for yourself. You should set `us-east-1` for the default region, and `None` for the format. The service will then auto-update itself at the next restart, by pulling from AWS S3.
