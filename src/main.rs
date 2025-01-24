use std::collections::HashMap;
use std::fs;
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};
use csv::ReaderBuilder;

fn main() {
    let dir = "/Users/fukusuke/Scripts/Python/hayabusa-rules"; // Specify the directory to search
    let mut event_id_counts: HashMap<String, usize> = HashMap::new();
    let mut category_counts: HashMap<String, (usize, bool)> = HashMap::new();
    let mut total_event_ids = 0;

    let event_mapping = load_event_mapping("channel_eid_info.txt");

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
    println!("| EventId | Event | Count | Percentage |");
    println!("|---------|-------|-------|------------|");
    for (event_id, count) in event_id_counts {
        let percentage = (*count as f64 / total_event_ids as f64) * 100.0;
        let msg = "".to_string();
        let event = event_mapping.get(event_id).unwrap_or(&msg);
        println!("| {} | {} | {} | {:.2}% |", event_id, event, count, percentage);
    }

    let mut category_counts: Vec<_> = category_counts.iter().collect();
    category_counts.sort_by(|a, b| b.1.cmp(a.1));

    let total_categories: usize = category_counts.iter().map(|(_, &(count, _))| count).sum();

    let category_mapping = load_category_mapping("mapping.csv");
    println!("---");
    println!("| Category/Service | Channel/EventID | Count | Percentage | Rules | Source |");
    println!("|------------------|-----------------|-------|------------|-------|--------|");
    for (category, &(count, is_category)) in category_counts {
        let percentage = (count as f64 / total_categories as f64) * 100.0;
        let rules = count; // Assuming each count represents a rule
        let source = if is_category { "sysmon" } else { "default" };
        if let Some(entry) = category_mapping.get(category) {
            let mut s = "".to_string();
            let mut i =0;
            for (ch, eid) in entry {
                if eid.is_empty() {
                    s.push_str(&format!("{}", ch));
                } else if entry.len() == 1 {
                    s.push_str(&format!("{}:{}", ch, eid));
                } else {
                    if i == entry.len() - 1 {
                        s.push_str(&format!("{}:{}", ch, eid));
                    } else {
                        s.push_str(&format!("{}:{}<br>", ch, eid));
                    }
                }
                i += 1;
            }
            println!("| {} | {} | {} | {:.2}% | {} | {} |", category, s, count, percentage, rules, source);
        } else {
            println!("| {} | N/A | {} | {:.2}% | {} | {} |", category, count, percentage, rules, source);
        }
    }
}

fn load_event_mapping(file_path: &str) -> HashMap<String, String> {
    let mut event_mapping = HashMap::new();
    if let Ok(content) = fs::read_to_string(file_path) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() == 3 {
                event_mapping.insert(parts[1].to_string(), parts[2].to_string());
            }
        }
    }
    event_mapping
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
        if service == "sysmon" {
            category_counts.entry(service.to_string()).or_insert((0, true)).0 += 1;
        } else {
            category_counts.entry(service.to_string()).or_insert((0, false)).0 += 1;
        }
    }

    if let Some(hash) = yaml.as_hash() {
        for (_, value) in hash {
            search_yaml(value, event_id_counts, category_counts, total_event_ids);
        }
    }
}

fn load_category_mapping(file_path: &str) -> HashMap<String, Vec<(String, String)>> {
    let mut category_mapping = HashMap::new();
    let mut rdr = ReaderBuilder::new().from_path(file_path).expect("Failed to open CSV file");
    for result in rdr.records() {
        let record = result.expect("Failed to read record");
        let category = record.get(0).unwrap_or("").to_string();
        let event_id = record.get(1).unwrap_or("").to_string();
        let channel = record.get(2).unwrap_or("").to_string();
        category_mapping.entry(category).or_insert_with(Vec::new).push((channel, event_id));
    }
    category_mapping
}