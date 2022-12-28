use crate::rustflowd::api::*;

pub struct SelectorEntity {
    packet_interval: u64,
    packet_space: u64,
}

impl SelectorEntity {
    pub fn new(selector_configuration: &ipfix::selection_process::Selector) -> SelectorEntity {
        SelectorEntity {
            packet_interval: selector_configuration.packet_interval.as_ref().unwrap().value,
            packet_space: selector_configuration.packet_space.as_ref().unwrap().value,
        }
    }
}

pub struct SelectionProcessEntity {
    name: String,
    selectors: Vec<SelectorEntity>,
}

impl SelectionProcessEntity {
    pub fn new(
        name: &String,
        selection_process_configuration: &ipfix::SelectionProcess,
    ) -> SelectionProcessEntity {
        let mut selectors: Vec<SelectorEntity> = Vec::new();
        for each_selector in &selection_process_configuration.selector {
            if let Some(selector) = &each_selector.selector {
                selectors.push(SelectorEntity::new(selector));
            }
        }
        SelectionProcessEntity {
            name: name.to_string(),
            selectors: Vec::new(),
        }
    }
}
