//! Exercise Slint's bundled fallback and Brazilian Portuguese plural rules.

include!(concat!(env!("OUT_DIR"), "/locale-fixture.rs"));

#[test]
fn bundled_portuguese_uses_english_fallback_and_plural_forms() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = LocaleFixture::new().unwrap();
    slint::select_bundled_translation("pt-BR").unwrap();
    assert_eq!(ui.get_translated(), "Mensagem traduzida");
    assert_eq!(ui.get_fallback(), "Untranslated message");
    for (count, expected) in [
        (0, "0 resultado"),
        (1, "1 resultado"),
        (2, "2 resultados"),
        (27, "27 resultados"),
    ] {
        ui.set_count(count);
        assert_eq!(ui.get_findings(), expected, "plural count: {count}");
    }
    slint::select_bundled_translation("en").unwrap();
    assert_eq!(ui.get_translated(), "Translated message");
}
