add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode"})
add_rules("mode.debug", "mode.release")
add_rules("plugin.vsxmake.autoupdate")
add_requires("cryptopp", "pybind11")
set_languages("c++17")


target("core")
    set_kind("static")
    add_packages("cryptopp")
    add_files("model_crypto/core/*.cpp")
    add_includedirs("model_crypto/core", {interface = true})


target("utils")
    set_kind("static")
    add_headerfiles("model_crypto/utils/*.h")
    add_includedirs("model_crypto/utils", {interface = true})


target("model_crypto")
    add_deps("core")
    set_kind("shared")
    set_extension(".pyd")
    add_packages("cryptopp", "pybind11")
    add_files("model_crypto/pybind/model_crypto.cpp")

    after_build(function (target)
            os.cp(
                "$(scriptdir)/build/**.pyd", 
                "$(scriptdir)/python/model_crypto/libs"
            )
        end
    )


target("Crypto")
    set_kind("binary")
    add_packages("cryptopp")
    add_deps("core", "utils")
    add_files("model_crypto/main.cpp")