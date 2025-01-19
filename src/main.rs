use std::collections::HashMap;
use std::fs;
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

fn main() {
    let dir = "/Users/fukusuke/Scripts/Python/hayabusa-rules"; // Specify the directory to search
    let mut event_id_counts: HashMap<String, usize> = HashMap::new();
    let mut category_counts: HashMap<String, (usize, bool)> = HashMap::new();
    let mut total_event_ids = 0;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file() && entry.path().extension().and_then(|s| s.to_str()) == Some("yml") {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(docs) = YamlLoader::load_from_str(&content) {
                    if let Some(yaml) = docs.get(0) {
                        search_yaml(&yaml, &mut event_id_counts, &mut category_counts, &mut total_event_ids);
                    }
                }
            }
        }
    }

    let mut event_id_counts: Vec<_> = event_id_counts.iter().collect();
    event_id_counts.sort_by(|a, b| b.1.cmp(a.1));

    println!("---");
    println!("| EventId | Count | Percentage |");
    println!("|---------|-------|------------|");
    for (event_id, count) in event_id_counts {
        let percentage = (*count as f64 / total_event_ids as f64) * 100.0;
        println!("| {} | {} | {:.2}% |", event_id, count, percentage);
    }

    let mut category_counts: Vec<_> = category_counts.iter().collect();
    category_counts.sort_by(|a, b| b.1.cmp(a.1));

    let total_categories: usize = category_counts.iter().map(|(_, &(count, _))| count).sum();

    println!("---");
    println!("| Category/Service | Count | Percentage | Source |");
    println!("|------------------|-------|------------|--------|");
    for (category, &(count, is_category)) in category_counts {
        let percentage = (count as f64 / total_categories as f64) * 100.0;
        let source = if is_category { "sysmon" } else { "" };
        println!("| {} | {} | {:.2}% | {} |", category, count, percentage, source);
    }
}

fn search_yaml(yaml: &Yaml, event_id_counts: &mut HashMap<String, usize>, category_counts: &mut HashMap<String, (usize, bool)>, total_event_ids: &mut usize) {
    if let Some(channel) = yaml["Channel"].as_str() {
        if channel == "Security" {
            if let Some(event_id) = yaml["EventID"].as_i64() {
                *event_id_counts.entry(event_id.to_string()).or_insert(0) += 1;
                *total_event_ids += 1;
            }
        }
    }

    if let Some(category) = yaml["logsource"]["category"].as_str() {
        category_counts.entry(category.to_string()).or_insert((0, true)).0 += 1;
    } else if let Some(service) = yaml["logsource"]["service"].as_str() {
        category_counts.entry(service.to_string()).or_insert((0, false)).0 += 1;
    }

    if let Some(hash) = yaml.as_hash() {
        for (_, value) in hash {
            search_yaml(value, event_id_counts, category_counts, total_event_ids);
        }
    }
}