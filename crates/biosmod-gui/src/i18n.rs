//! GUI language preferences. Engine arguments and process locales remain unchanged.

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Language {
    #[default]
    #[serde(rename = "en")]
    En,
    #[serde(rename = "pt-BR")]
    PtBr,
}

impl Language {
    /// Return the bundled catalog identifier. Example: `Language::PtBr.identifier()` is `pt-BR`.
    pub fn identifier(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::PtBr => "pt-BR",
        }
    }

    /// Return the language selector index. Example: `Language::PtBr.index()` is `1`.
    pub fn index(self) -> i32 {
        i32::from(self == Self::PtBr)
    }

    /// Select embedded translations on the UI thread after constructing a component.
    /// Example: `Language::En.select()?` explicitly overrides environment locale detection.
    pub fn select(self) -> Result<(), slint::SelectBundledTranslationError> {
        slint::select_bundled_translation(self.identifier())
    }
}

impl<'de> Deserialize<'de> for Language {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Consume any JSON value: a bad language must not discard valid theme/engine fields.
        let value = serde_json::Value::deserialize(deserializer)?;
        let normalized = value
            .as_str()
            .unwrap_or_default()
            .replace('_', "-")
            .to_ascii_lowercase();
        Ok(match normalized.as_str() {
            "pt-br" | "pt-br.utf-8" | "pt-br.utf8" => Self::PtBr,
            _ => Self::En,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_identifiers_and_aliases() {
        for value in ["pt-BR", "pt-br", "pt_BR", "pt_BR.UTF-8"] {
            let language: Language = serde_json::from_value(serde_json::json!(value)).unwrap();
            assert_eq!(language, Language::PtBr, "language alias: {value}");
            assert_eq!(language.identifier(), "pt-BR");
            assert_eq!(language.index(), 1);
            assert_eq!(serde_json::to_string(&language).unwrap(), "\"pt-BR\"");
        }
        for value in [
            serde_json::json!("pt-PT"),
            serde_json::json!("de"),
            serde_json::json!(42),
            serde_json::json!(null),
            serde_json::json!({}),
        ] {
            let language: Language = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(language, Language::En, "unsupported language: {value}");
            assert_eq!(language.identifier(), "en");
            assert_eq!(language.index(), 0);
        }
    }

    #[test]
    fn bundled_language_selection_is_explicit_and_reversible() {
        i_slint_backend_testing::init_no_event_loop();
        let _ui = crate::ui::AppWindow::new().unwrap();
        Language::En.select().unwrap();
        Language::PtBr.select().unwrap();
        Language::En.select().unwrap();
    }
}
