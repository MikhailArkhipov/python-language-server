﻿// Copyright(c) Microsoft Corporation
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the License); you may not use
// this file except in compliance with the License. You may obtain a copy of the
// License at http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY
// IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
// MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache Version 2.0 License for specific language governing
// permissions and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Python.Analysis.Analyzer;
using Microsoft.Python.Analysis.Core.DependencyResolution;
using Microsoft.Python.Analysis.Core.Interpreter;
using Microsoft.Python.Analysis.Modules;
using Microsoft.Python.Analysis.Types;
using Microsoft.Python.Core;
using Microsoft.Python.Core.IO;

namespace Microsoft.Python.Analysis.Caching {
    internal static class ModuleUniqueId {
        private static ConcurrentDictionary<AnalysisModuleKey, string> _idCache = new ConcurrentDictionary<AnalysisModuleKey, string>();

        public static string GetUniqueId(this IPythonModule module, IServiceContainer services, AnalysisCachingLevel cachingLevel = AnalysisCachingLevel.Library) {
            // If module is a standalone stub, permit it. Otherwise redirect to the main module
            // since during stub merge types from stub normally become part of the primary module.
            if (module.ModuleType == ModuleType.Stub && module.PrimaryModule != null) {
                module = module.PrimaryModule;
            }
            return GetUniqueId(module.Name, module.FilePath, module.ModuleType, services, cachingLevel);
        }

        public static string GetUniqueId(string moduleName, string filePath, ModuleType moduleType, 
            IServiceContainer services, AnalysisCachingLevel cachingLevel = AnalysisCachingLevel.Library) {
            if(cachingLevel == AnalysisCachingLevel.None) {
                return null;
            }

            var interpreter = services.GetService<IPythonInterpreter>();
            var fs = services.GetService<IFileSystem>();

            var moduleResolution = interpreter.ModuleResolution;
            var modulePathType = GetModulePathType(filePath, moduleResolution.LibraryPaths, fs);
            switch(modulePathType) {
                case PythonLibraryPathType.Site when cachingLevel < AnalysisCachingLevel.Library:
                    return null;
                case PythonLibraryPathType.StdLib when cachingLevel < AnalysisCachingLevel.System:
                    return null;
            }

            if (!string.IsNullOrEmpty(filePath) && modulePathType == PythonLibraryPathType.Site) {
                var key = new AnalysisModuleKey(moduleName, filePath);
                if (_idCache.TryGetValue(key, out var id)) {
                    return id;
                }

                // Module can be a submodule of a versioned package. In this case we want to use
                // version of the enclosing package so we have to look up the chain of folders.
                var moduleRootName = moduleName.Split('.')[0];
                var moduleFilesFolder = Path.GetDirectoryName(filePath);
                var installationFolder = Path.GetDirectoryName(moduleFilesFolder);

                var versionFolder = installationFolder;
                while (!string.IsNullOrEmpty(versionFolder)) {
                    // If module is in site-packages and is versioned, then unique id = name + version + interpreter version.
                    // Example: 'requests' and 'requests-2.21.0.dist-info'.
                    // TODO: for egg (https://github.com/microsoft/python-language-server/issues/196), consider *.egg-info
                    var folders = fs.GetFileSystemEntries(versionFolder, "*-*.dist-info", SearchOption.TopDirectoryOnly)
                        .Select(Path.GetFileName)
                        .Where(n => n.StartsWith(moduleRootName, StringComparison.OrdinalIgnoreCase)) // Module name can be capitalized differently.
                        .ToArray();

                    if (folders.Length == 1) {
                        var fileName = Path.GetFileNameWithoutExtension(folders[0]);
                        var dash = fileName.IndexOf('-');
                        var uniqueId = $"{moduleName}({fileName.Substring(dash + 1)})";
                        _idCache[key] = uniqueId;
                        return uniqueId;
                    }
                    // Move up if nothing is found.
                    versionFolder = Path.GetDirectoryName(versionFolder);
                }
            }

            var config = interpreter.Configuration;
            if (moduleType == ModuleType.CompiledBuiltin || string.IsNullOrEmpty(filePath) || modulePathType == PythonLibraryPathType.StdLib) {
                // If module is a standard library, unique id is its name + interpreter version.
                return $"{moduleName}({config.Version.Major}.{config.Version.Minor})";
            }

            var parent = moduleResolution.CurrentPathResolver.GetModuleParentFromModuleName(moduleName);
            if (parent == null) {
                return moduleName;
            }

            var hash = HashModuleFileSizes(parent);
            // If all else fails, hash modules file sizes.
            return $"{moduleName}.{(ulong)hash}";
        }

        private static long HashModuleFileSizes(IImportChildrenSource source) {
            var hash = 0L;
            var names = source.GetChildrenNames();
            foreach (var name in names) {
                if (source.TryGetChildImport(name, out var child)) {
                    if (child is ModuleImport moduleImport) {
                        if (moduleImport.ModuleFileSize == 0) {
                            continue; // Typically test case, memory-only module.
                        }
                        hash = unchecked(hash * 31 ^ moduleImport.ModuleFileSize);
                    }

                    if (child is IImportChildrenSource childSource) {
                        hash = unchecked(hash * 31 ^ HashModuleFileSizes(childSource));
                    }
                }
            }

            return hash;
        }

        private static PythonLibraryPathType GetModulePathType(string modulePath, IEnumerable<PythonLibraryPath> libraryPaths, IFileSystem fs) {
            if (string.IsNullOrEmpty(modulePath)) {
                return PythonLibraryPathType.Unspecified;
            }
            return libraryPaths
                .OrderByDescending(p => p.Path.Length)
                .FirstOrDefault(p => fs.IsPathUnderRoot(p.Path, modulePath))?.Type ?? PythonLibraryPathType.Unspecified;
        }
    }
}
