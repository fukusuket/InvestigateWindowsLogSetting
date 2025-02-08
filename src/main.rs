use csv::{ReaderBuilder, Writer};
use std::collections::HashMap;
use std::error::Error;
use std::{env, fs};
use std::fs::File;
use std::io::Write;
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory>", args[0]);
        std::process::exit(1);
    }
    let dir = &args[1];
    let mut event_id_counts: HashMap<String, usize> = HashMap::new();
    let mut category_counts: HashMap<String, (usize, bool)> = HashMap::new();
    let mut total_event_ids = 0;

    let event_mapping = load_event_mapping("channel_eid_info.txt");

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file()
            && entry.path().extension().and_then(|s| s.to_str()) == Some("yml")
        {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(docs) = YamlLoader::load_from_str(&content) {
                    if let Some(yaml) = docs.get(0) {
                        search_yaml(
                            &yaml,
                            &mut event_id_counts,
                            &mut category_counts,
                            &mut total_event_ids,
                        );
                    }
                }
            }
        }
    }

    let mut event_id_counts: Vec<_> = event_id_counts.iter().collect();
    event_id_counts.sort_by(|a, b| b.1.cmp(a.1));

    let mut md_file = File::create("security_eid.md")?;
    md_file
        .write_all("| EventId | Event | Count | Percentage |\n".as_bytes())
        .ok();
    md_file
        .write_all("|---------|-------|-------|------------|\n".as_bytes())
        .ok();
    let file = File::create("security_eid.csv")?;
    let mut wtr = Writer::from_writer(file);
    wtr.write_record(&["EventId", "Event", "Count", "Percentage"])?;
    for (event_id, count) in event_id_counts.iter().take(20) {
        let percentage = (**count as f64 / total_event_ids as f64) * 100.0;
        let msg = "".to_string();
        let event = event_mapping.get(*event_id).unwrap_or(&msg);
        md_file
            .write_all(
                format!(
                    "| {} | {} | {} | {:.2}% |\n",
                    event_id, event, count, percentage
                )
                .as_bytes(),
            )
            .ok();
        let percentage = format!("{:.2}%", percentage);
        wtr.write_record(&[event_id, event, &count.to_string(), &percentage])?;
    }
    wtr.flush()?;

    let mut category_counts: Vec<_> = category_counts.iter().collect();
    category_counts.sort_by(|a, b| b.1.cmp(a.1));

    let total_categories: usize = category_counts.iter().map(|(_, &(count, _))| count).sum();
    let category_mapping = load_category_mapping("mapping.csv");

    let mut md_file = File::create("sigma_eid.md")?;
    md_file
        .write_all(
            "| Category/Service | Channel/EventID | Count | Percentage | Rules | Source |\n"
                .as_bytes(),
        )
        .ok();
    md_file
        .write_all(
            "|------------------|-----------------|-------|------------|-------|--------|\n"
                .as_bytes(),
        )
        .ok();
    let file = File::create("sigma_eid.csv")?;
    let mut wtr = Writer::from_writer(file);
    wtr.write_record(&[
        "Category/Service",
        "Channel/EventID",
        "Count",
        "Percentage",
        "Rules",
        "Source",
    ])?;
    for (category, &(count, is_category)) in category_counts.iter().take(20) {
        let percentage = (count as f64 / total_categories as f64) * 100.0;
        let rules = count; // Assuming each count represents a rule
        let mut source = if is_category { "sysmon" } else { "default" };
        if *category == "ps_script" {
            source = "default";
        }
        let mut source = source.to_string();
        if let Some(entry) = category_mapping.get(*category) {
            let mut s = "".to_string();
            for (i, (ch, eid)) in entry.iter().enumerate() {
                if eid.is_empty() {
                    s.push_str(&format!("{}", ch));
                } else if entry.len() == 1 {
                    s.push_str(&format!("{}:{}", ch, eid));
                } else {
                    if i == entry.len() - 1 {
                        s.push_str(&format!("{}:{}", ch, eid));
                    } else {
                        s.push_str(&format!("{}:{}<br>", ch, eid));
                        source.push_str(&format!("<br>{}", "non-default"));
                    }
                }
            }
            md_file
                .write_all(
                    format!(
                        "| {} | {} | {} | {:.2}% | {} | {} |\n",
                        category, s, count, percentage, rules, source
                    )
                    .as_bytes(),
                )
                .ok();
            let percentage = format!("{:.2}%", percentage);
            wtr.write_record(&[
                category,
                &s,
                &count.to_string(),
                &percentage,
                &rules.to_string(),
                &source.to_string(),
            ])?;
        } else {
            md_file
                .write_all(
                    format!(
                        "| {} | N/A | {} | {:.2}% | {} | {} |\n",
                        category, count, percentage, rules, source
                    )
                    .as_bytes(),
                )
                .ok();
            let percentage = format!("{:.2}%", percentage);
            wtr.write_record(&[
                category,
                "N/A",
                &count.to_string(),
                &percentage,
                &rules.to_string(),
                &source.to_string(),
            ])?;
        }
    }
    Ok(())
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

fn search_yaml(
    yaml: &Yaml,
    event_id_counts: &mut HashMap<String, usize>,
    category_counts: &mut HashMap<String, (usize, bool)>,
    total_event_ids: &mut usize,
) {
    if let Some(channel) = yaml["Channel"].as_str() {
        if channel == "Security" {
            if let Some(event_id) = yaml["EventID"].as_i64() {
                *event_id_counts.entry(event_id.to_string()).or_insert(0) += 1;
                *total_event_ids += 1;
            }
        }
    }

    if let Some(category) = yaml["logsource"]["category"].as_str() {
        category_counts
            .entry(category.to_string())
            .or_insert((0, true))
            .0 += 1;
    } else if let Some(service) = yaml["logsource"]["service"].as_str() {
        if service == "sysmon" {
            category_counts
                .entry(service.to_string())
                .or_insert((0, true))
                .0 += 1;
        } else {
            category_counts
                .entry(service.to_string())
                .or_insert((0, false))
                .0 += 1;
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
    let mut rdr = ReaderBuilder::new()
        .from_path(file_path)
        .expect("Failed to open CSV file");
    for result in rdr.records() {
        let record = result.expect("Failed to read record");
        let category = record.get(0).unwrap_or("").to_string();
        let event_id = record.get(1).unwrap_or("").to_string();
        let channel = record.get(2).unwrap_or("").to_string();
        category_mapping
            .entry(category)
            .or_insert_with(Vec::new)
            .push((channel, event_id));
    }
    category_mapping
}
