#![cfg(feature = "test-fixtures")]

use cc_wallet_domain::{ActivityEnvelope, ActivityEvent};

fn outcome(bytes: &[u8]) -> &'static str {
    match ActivityEnvelope::decode(bytes) {
        Ok(_) => "OK",
        Err(_) => "ERR",
    }
}

fn walk(value: &serde_json::Value, prefix: String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.push(path.clone());
                walk(v, path, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                walk(v, format!("{prefix}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn at<'a>(value: &'a mut serde_json::Value, path: &str) -> Option<&'a mut serde_json::Value> {
    let mut cur = value;
    for step in path.split('.') {
        let (name, indices) = match step.find('[') {
            Some(i) => (&step[..i], &step[i..]),
            None => (step, ""),
        };
        cur = cur.as_object_mut()?.get_mut(name)?;
        for idx in indices.split(']').filter(|s| !s.is_empty()) {
            let i: usize = idx.trim_start_matches('[').parse().ok()?;
            cur = cur.as_array_mut()?.get_mut(i)?;
        }
    }
    Some(cur)
}

fn remove(value: &mut serde_json::Value, path: &str) -> bool {
    let (parent, last) = match path.rfind('.') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    };
    let target = if parent.is_empty() {
        Some(value)
    } else {
        at(value, parent)
    };
    match target.and_then(|v| v.as_object_mut()) {
        Some(map) => map.remove(last).is_some(),
        None => false,
    }
}

#[test]
fn the_activity_wire_accepts_and_rejects_exactly_what_it_did_before() {
    let mut event = ActivityEvent::test_stub(7, 1_700_000_000);
    event.exit_code = -3;
    let json = String::from_utf8(
        ActivityEnvelope::new(vec![ActivityEvent::test_stub(6, 1_699_999_999), event])
            .encode()
            .expect("the fixture encodes"),
    )
    .expect("the encoding is utf-8");

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let mut paths = Vec::new();
    walk(&parsed, String::new(), &mut paths);
    paths.sort();

    let mut report = vec![format!("baseline {}", outcome(json.as_bytes()))];

    for path in &paths {
        let mut missing = parsed.clone();
        if remove(&mut missing, path) {
            report.push(format!(
                "remove {path} -> {}",
                outcome(missing.to_string().as_bytes())
            ));
        }

        let mut nulled = parsed.clone();
        if let Some(slot) = at(&mut nulled, path) {
            *slot = serde_json::Value::Null;
            report.push(format!(
                "null {path} -> {}",
                outcome(nulled.to_string().as_bytes())
            ));
        }

        let mut retyped = parsed.clone();
        if let Some(slot) = at(&mut retyped, path) {
            *slot = match &*slot {
                serde_json::Value::String(_) => serde_json::json!(9),
                _ => serde_json::json!("9"),
            };
            report.push(format!(
                "retype {path} -> {}",
                outcome(retyped.to_string().as_bytes())
            ));
        }
    }

    let unknown = json.replacen("{\"", "{\"surprise\":1,\"", 1);
    report.push(format!("unknown-key -> {}", outcome(unknown.as_bytes())));

    let duplicate = json.replacen("\"lt\":6", "\"lt\":6,\"lt\":6", 1);
    report.push(format!("duplicate-lt -> {}", outcome(duplicate.as_bytes())));

    let truncated = &json.as_bytes()[..json.len() / 2];
    report.push(format!("truncated -> {}", outcome(truncated)));

    let rendered = report.join("\n");
    let expected = include_str!("wire_golden.txt");
    assert_eq!(
        rendered.trim(),
        expected.trim(),
        "the activity wire's accept/reject matrix moved"
    );
}
