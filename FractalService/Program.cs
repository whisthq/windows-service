﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using Sentry;

namespace FractalService
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            // Initialize Sentry
            using (SentrySdk.Init("https://147514cde6004c8ca8171f1f37c2a919@o400459.ingest.sentry.io/5493264"))
            {
                // App code
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                new FractalService()
                };
                ServiceBase.Run(ServicesToRun);
            }
        }
    }
}
