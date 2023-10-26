add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode"})
add_rules("mode.debug", "mode.release")
add_rules("plugin.vsxmake.autoupdate")
add_requires("cryptopp", "pybind11")


target("crypto_core")
    set_kind("static")
    set_basename("core") 
    add_packages("cryptopp")
    add_files("model_crypto/core/*.cpp")
    add_includedirs("model_crypto/core", {interface = true})


target("crypto_utils")
    set_kind("static")
    set_basename("utils") 
    add_headerfiles("model_crypto/utils/*.hpp")
    add_includedirs("model_crypto/utils", {interface = true})


target("core")
    set_kind("shared")
    add_deps("crypto_core")
    add_packages("cryptopp", "pybind11")
    add_rules("python.library", {soabi = true})
    add_files("model_crypto/pybind/core.cpp")


target("utils")
    set_kind("shared")
    add_deps("crypto_utils")
    add_packages("pybind11")
    add_rules("python.library", {soabi = true})
    add_files("model_crypto/pybind/utils.cpp")


before_build(function (target)
    if is_mode("release") then
        os.mkdir("$(projectdir)/lib")
        os.mkdir("$(projectdir)/include/core")
        os.mkdir("$(projectdir)/include/utils")
        os.cp("$(projectdir)/model_crypto/core/*.hpp", "$(projectdir)/include/core/")
        os.cp("$(projectdir)/model_crypto/utils/*.hpp", "$(projectdir)/include/utils/")
        os.cp("$(projectdir)/build/**/core.lib", "$(projectdir)/lib/")
        -- os.cp("$(projectdir)/build/**/utils.lib", "$(projectdir)/lib/")
    end
    os.mkdir("$(scriptdir)/python/model_crypto/libs")
    os.cp("$(projectdir)/build/**.pyd", "$(projectdir)/python/model_crypto/libs/")
end)