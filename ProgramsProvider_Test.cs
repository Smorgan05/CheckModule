﻿//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

namespace Microsoft.PackageManagement.Providers.Internal
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.AccessControl;
    using Microsoft.PackageManagement.Internal.Implementation;
    using Microsoft.PackageManagement.Internal.Packaging;
    using Microsoft.PackageManagement.Internal.Utility.Extensions;
    using Microsoft.Win32;

    public class ProgramsProvider
    {
        // The name of this Package Provider
        internal const string ProviderName = "Programs";

        private static readonly Dictionary<string, string[]> _features = new Dictionary<string, string[]>();

        // Returns the name of the Provider.
        public string GetPackageProviderName()
        {
            return ProviderName;
        }

        // InitializeProvider - Performs one-time initialization of the PROVIDER.
        // Request - An object passed in from the CORE that contains functions that can be used to interact with the CORE and HOST
        public void InitializeProvider(Request request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }
            // Nice-to-have put a debug message in that tells what's going on.
            request.Debug("Calling '{0}::InitializeProvider'", ProviderName);
        }

        // GetFeatures - Returns a collection of strings to the client advertizing features this provider supports.
        // Request - An object passed in from the CORE that contains functions that can be used to interact with the CORE and HOST
        public void GetFeatures(Request request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            // Nice-to-have put a debug message in that tells what's going on.
            request.Debug("Calling '{0}::GetFeatures' ", ProviderName);

            foreach (var feature in _features)
            {
                request.Yield(feature);
            }
        }

        // GetDynamicOptions - Returns dynamic option definitions to the HOST
        // Category - The category of dynamic options that the HOST is interested in</param>
        // Request - An object passed in from the CORE that contains functions that can be used to interact with the CORE and HOST
        public void GetDynamicOptions(string category, Request request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            category = category ?? string.Empty;

            // Nice-to-have put a debug message in that tells what's going on.
            request.Debug("Calling '{0}::GetDynamicOptions' '{1}'", ProviderName, category);

            switch (category.ToLowerInvariant())
            {
                case "install":
                    // options required for install/uninstall/getinstalledpackages
                    request.YieldDynamicOption("IncludeWindowsInstaller", "Switch", false);
                    request.YieldDynamicOption("IncludeSystemComponent", "Switch", false);
                    break;

                case "provider":
                    // options used with this provider. Not currently used.
                    break;

                case "source":
                    // options for package sources
                    break;

                case "package":
                    // options used when searching for packages
                    break;
            }
        }


        // GetInstalledPackages - Returns the packages that are installed
        // Name - the package name to match. Empty or null means match everything

        public void GetInstalledPackages(string name, string requiredVersion, string minimumVersion, string maximumVersion, Request request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }
            // Nice-to-have put a debug message in that tells what's going on.
            request.Debug("Calling '{0}::GetInstalledPackages' '{1}','{2}','{3}','{4}'", ProviderName, name, requiredVersion, minimumVersion, maximumVersion);

            // dump out results.

            if (Environment.Is64BitOperatingSystem)
            {
                using (var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey))
                {
                    if (!YieldPackages("hklm64", hklm64, name, requiredVersion, minimumVersion, maximumVersion, request))
                    {
                        return;
                    }
                }

                using (var hkcu64 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false))
                {
                    if (!YieldPackages("hkcu64", hkcu64, name, requiredVersion, minimumVersion, maximumVersion, request))
                    {
                        return;
                    }
                }
            }

            using (var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false))
            {
                if (!YieldPackages("hklm32", hklm32, name, requiredVersion, minimumVersion, maximumVersion, request))
                {
                    return;
                }
            }

            using (var hkcu32 = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry32).OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false))
            {
                if (!YieldPackages("hkcu32", hkcu32, name, requiredVersion, minimumVersion, maximumVersion, request))
                {
                }
            }
        }

        // YieldPackages - Use a foreach (Pipeline) loop to cycle through the Uninstall Keys as specified by the Hive and RegKey.  
        // From there in the loop if the result returns True then display the result or when the request is null display all software installed for the Programs Provider.
        // Hive - HKLM / HKCU
        // RegKey - SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
        private bool YieldPackages(string hive, RegistryKey regkey, string name, string requiredVersion, string minimumVersion, string maximumVersion, Request request) {
            if (regkey != null) {
                var includeWindowsInstaller = request.GetOptionValue("IncludeWindowsInstaller").IsTrue();
                var includeSystemComponent = request.GetOptionValue("IncludeSystemComponent").IsTrue();

                //var wildcardPattern = new WildcardPattern(name??"", WildcardOptions.CultureInvariant | WildcardOptions.IgnoreCase);

                // Iterate through each Key and pull the values as necessary
                foreach (var key in regkey.GetSubKeyNames()) {
                    var subkey = regkey.OpenSubKey(key);
                    if (subkey != null) {
                        var properties = subkey.GetValueNames().ToDictionaryNicely(each => each.ToString(), each => (subkey.GetValue(each) ?? string.Empty).ToString(), StringComparer.OrdinalIgnoreCase);

                        if (!includeWindowsInstaller && properties.ContainsKey("WindowsInstaller") && properties["WindowsInstaller"] == "1") {
                            continue;
                        }

                        if (!includeSystemComponent && properties.ContainsKey("SystemComponent") && properties["SystemComponent"] == "1") {
                            continue;
                        }

                        /*
                     
                        var productName = "";

                        if (!properties.TryGetValue("DisplayName", out productName)) {
                            // no product name?
                            continue;
                        }
                        

                        if (!string.IsNullOrWhiteSpace(productName) && (string.IsNullOrWhiteSpace(name) || wildcardPattern.IsMatch(productName)))
                        {

                        */

                        var productName = properties.Get("DisplayName");
                       // var productVersion = properties.Get("DisplayVersion") ?? "";
                        var productVersion = properties.Get("DisplayVersion") ?? VerFinder();
                        var publisher = properties.Get("Publisher") ?? "";
                        var comments = properties.Get("Comments") ?? "";
                        var FullPath = hive + @"\" + subkey;

                        // Pull based off Pattern Match 
                        var uninstallString = properties.Get("QuietUninstallString") ?? properties.Get("UninstallString") ?? "";

                        if (!string.IsNullOrEmpty(requiredVersion))
                            {
                                if (SoftwareIdentityVersionComparer.CompareVersions("unknown", requiredVersion, productVersion) != 0)
                                {
                                    continue;
                                }
                        }
                        else
                        {
                            if (!string.IsNullOrEmpty(minimumVersion) && SoftwareIdentityVersionComparer.CompareVersions("unknown", productVersion, minimumVersion) < 0)
                            {
                                continue;
                            }
                            if (!string.IsNullOrEmpty(maximumVersion) && SoftwareIdentityVersionComparer.CompareVersions("unknown", productVersion, maximumVersion) > 0)
                            {
                                continue;
                            }
                        }

                        if (request.YieldSoftwareIdentity(FullPath, productName, productVersion, "unknown", comments, "", name, "", "") != null)
                        {
                            if (properties.Keys.Where(each => !string.IsNullOrWhiteSpace(each)).Any(k => request.AddMetadata(FullPath, k.MakeSafeFileName(), properties[k]) == null))
                            {
                                return false;
                            }
                        }

                        //}
                    }
                }
            }
            return true;
        }
    }
}

