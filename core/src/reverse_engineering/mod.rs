use crate::util::SResult;
use serde::{Deserialize, Serialize};

const K1_TSL_IMPORT_MAP_JSON: &str =
    include_str!("../../assets/reverse_engineering/k1_tsl_import_map.json");

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossBinaryMap {
    pub generated_at: String,
    pub generated_from: String,
    pub confidence: String,
    pub note: String,
    pub section_anchors: Vec<SectionAnchor>,
    pub bookmark_anchors: Vec<BookmarkAnchor>,
    pub internal_functions: Vec<InternalFunctionMapping>,
    pub imports: ImportMappingCollection,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SectionAnchor {
    pub name: String,
    pub k1: String,
    pub tsl: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BookmarkAnchor {
    pub category: String,
    pub k1: String,
    pub tsl: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InternalFunctionMapping {
    pub name: String,
    pub group: String,
    pub k1: Option<String>,
    pub tsl: Option<String>,
    pub confidence: String,
    pub status: String,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportMappingCollection {
    pub shared: Vec<SharedImportMapping>,
    pub k1_only: Vec<SingleSidedImportMapping>,
    pub tsl_only: Vec<SingleSidedImportMapping>,
    pub counts: ImportMappingCounts,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SharedImportMapping {
    pub symbol: String,
    pub k1: String,
    pub tsl: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SingleSidedImportMapping {
    pub symbol: String,
    #[serde(default)]
    pub k1: String,
    #[serde(default)]
    pub tsl: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportMappingCounts {
    pub k1: usize,
    pub tsl: usize,
    pub shared: usize,
    pub k1_only: usize,
    pub tsl_only: usize,
}

impl CrossBinaryMap {
    pub fn shared_import(&self, symbol: &str) -> Option<&SharedImportMapping> {
        self.imports.shared.iter().find(|item| item.symbol == symbol)
    }

    pub fn section_anchor(&self, name: &str) -> Option<&SectionAnchor> {
        self.section_anchors.iter().find(|item| item.name == name)
    }

    pub fn internal_function(&self, name: &str) -> Option<&InternalFunctionMapping> {
        self.internal_functions.iter().find(|item| item.name == name)
    }
}

pub fn load_embedded_k1_tsl_import_map() -> SResult<CrossBinaryMap> {
    serde_json::from_str(K1_TSL_IMPORT_MAP_JSON)
        .map_err(|err| format!("load_embedded_k1_tsl_import_map| {err}"))
}

#[cfg(test)]
mod tests {
    use super::load_embedded_k1_tsl_import_map;

    #[test]
    fn bundled_import_map_parses() {
        let map = load_embedded_k1_tsl_import_map().expect("bundled map should parse");

        assert_eq!(map.imports.counts.k1, 172);
        assert_eq!(map.imports.counts.tsl, 175);
        assert_eq!(map.imports.counts.shared, 163);
        assert_eq!(map.imports.counts.k1_only, 9);
        assert_eq!(map.imports.counts.tsl_only, 12);
    }

    #[test]
    fn direct_input_anchor_matches_expected_addresses() {
        let map = load_embedded_k1_tsl_import_map().expect("bundled map should parse");
        let direct_input = map
            .shared_import("DirectInput8Create")
            .expect("DirectInput8Create should be present");

        assert_eq!(direct_input.k1, "EXTERNAL:00000153");
        assert_eq!(direct_input.tsl, "EXTERNAL:00000143");
    }

    #[test]
    fn string_table_anchor_matches_expected_addresses() {
        let map = load_embedded_k1_tsl_import_map().expect("bundled map should parse");
        let anchor = map
            .section_anchor("import_string_table")
            .expect("import string table anchor should be present");

        assert_eq!(anchor.k1, "0x0078b146");
        assert_eq!(anchor.tsl, "0x009f17a2");
    }

    #[test]
    fn recovered_internal_entry_anchor_matches_expected_addresses() {
        let map = load_embedded_k1_tsl_import_map().expect("bundled map should parse");
        let entry = map
            .internal_function("pe_entry")
            .expect("recovered PE entry anchor should be present");

        assert_eq!(entry.k1.as_deref(), Some("0x0086d2ed"));
        assert_eq!(entry.tsl.as_deref(), Some("0x0091d5a2"));
        assert_eq!(entry.status, "recovered");
    }
}