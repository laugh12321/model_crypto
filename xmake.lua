add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode"})
add_rules("mode.debug", "mode.release")
add_rules("plugin.vsxmake.autoupdate")
add_requires("cryptopp")

target("TRTCrypto")
    set_kind("static")
    add_packages("cryptopp")
    add_files("TRTCrypto/*.cpp")
    

target("test")
    set_kind("binary")
    set_rundir("workspace")
    add_packages("cryptopp")
    add_files("test/*.cpp")
    add_includedirs("TRTCrypto")
    add_files("TRTCrypto/*.cpp")