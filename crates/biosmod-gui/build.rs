fn main() {
    // slint-build reads this variable but does not register it as a build input.
    println!("cargo:rerun-if-env-changed=SLINT_COMPILER_DENY_WARNINGS");
    // The fixture has a deliberately incomplete catalog to exercise fallback.
    slint_build::compile_with_config(
        "tests/locale-fixture.slint",
        slint_build::CompilerConfiguration::new()
            .with_style("fluent".into())
            .with_bundled_translations("tests/locale-fixture"),
    )
    .expect("compile locale test fixture");

    // Element debug info lets tests find widgets by accessible label; release builds omit it.
    let debug = std::env::var("PROFILE").is_ok_and(|profile| profile != "release");
    slint_build::compile_with_config(
        "ui/app-window.slint",
        slint_build::CompilerConfiguration::new()
            .with_style("fluent".into())
            .with_bundled_translations("i18n")
            .with_debug_info(debug),
    )
    .expect("compile desktop interface");
}
