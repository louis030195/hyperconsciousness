// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com
//! Typed, grant-scoped health evidence. Immutable logs remain authority.
use crate::{
    error::{Error, Result},
    grant::{Grant, Item, READ},
    id::{DeviceId, Hash},
    keyring::DataKeys,
    log::Store,
};
use chrono::{DateTime, NaiveDate, TimeZone};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Stored only inside authenticated encrypted derived shards.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub reference: String,
    pub record_id: String,
    pub at: u64,
    pub kind: String,
    pub tags: Vec<String>,
    pub sensitivity: u8,
    pub event: Value,
}
impl Evidence {
    pub fn item(&self) -> Item {
        Item {
            at: self.at,
            kind: self.kind.clone(),
            tags: self.tags.clone(),
            sensitivity: self.sensitivity,
        }
    }
}

pub fn payload_event(payload: &[u8]) -> Option<Value> {
    let p: Value = serde_json::from_slice(payload).ok()?;
    // Explicit structured contract. Never guess medical values from arbitrary prose.
    if let Some(e) = p.get("health").filter(|e| e.is_object()) {
        return Some(e.clone());
    }
    p.get("health_sync")
        .filter(|s| s.is_object())
        .map(|s| json!({"sync_status":s}))
}

pub struct Answer {
    pub value: Value,
    pub read_receipt: String,
}

#[allow(clippy::too_many_arguments)]
pub fn indexed<K: DataKeys + ?Sized>(
    store: &Store,
    keys: &K,
    index: &crate::search_index::Index,
    permissions: &crate::revocation::Index,
    chain: &[Grant],
    authority: DeviceId,
    now: u64,
    tool: &str,
    args: &Value,
) -> Result<Answer> {
    let effective = super::read_grant_indexed(store, keys, chain, authority, now, permissions)?;
    let captures = index.capture_state_shared(keys)?;
    let metrics: Vec<&str> = args["metrics"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let rows = index.health_evidence(store, keys, &metrics)?;
    let allowed: Vec<_> = rows
        .iter()
        .filter(|e| {
            Hash::from_hex(&e.record_id).is_some_and(|id| captures.visible(id, false))
                && chain.iter().all(|g| g.allows(&e.item(), READ, now))
        })
        .collect();
    let value = analyze(&allowed, tool, args, now)?;
    // Ordinary appends may advance heads during calculation. Catch up the
    // authenticated permission fold rather than rejecting harmless read receipts.
    let mut release_permissions = permissions.clone();
    if !release_permissions.refresh(store, keys)? {
        return Err(Error::Denied("health permission catch-up changed; retry"));
    }
    super::read_grant_indexed(
        store,
        keys,
        chain,
        authority,
        crate::Clock::new().now().millis,
        &release_permissions,
    )?;
    index.validate_read(store, keys, chain)?;
    Ok(Answer {
        read_receipt: super::receipt(effective, allowed.len(), 0, false, Some(tool), now),
        value,
    })
}

pub(crate) fn metric(t: &str) -> &str {
    match t {
        "HKQuantityTypeIdentifierHeartRateVariabilitySDNN" => "hrv_sdnn",
        "hrv_rmssd" | "OuraHRVRMSSD" => "hrv_rmssd",
        "HKQuantityTypeIdentifierRestingHeartRate" => "resting_heart_rate",
        "HKQuantityTypeIdentifierHeartRate" => "heart_rate",
        "HKQuantityTypeIdentifierStepCount" => "steps",
        "HKCategoryTypeIdentifierSleepAnalysis" => "sleep",
        "HKQuantityTypeIdentifierRespiratoryRate" => "respiratory_rate",
        "HKQuantityTypeIdentifierBodyMass" => "weight",
        "HKQuantityTypeIdentifierVO2Max" => "vo2_max",
        "HKQuantityTypeIdentifierActiveEnergyBurned" => "active_energy",
        "HKWorkoutTypeIdentifier" => "workout",
        other => other,
    }
}
fn normalize(metric: &str, unit: &str, value: f64) -> Option<(f64, String)> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let (scale, canonical) = match (metric, unit) {
        ("hrv_sdnn" | "hrv_rmssd", "ms") => (1.0, "ms"),
        ("hrv_sdnn" | "hrv_rmssd", "s") => (1000.0, "ms"),
        ("hrv_sdnn" | "hrv_rmssd", _) => return None,
        ("heart_rate" | "resting_heart_rate" | "respiratory_rate", "count/min" | "bpm") => {
            (1.0, "count/min")
        }
        ("heart_rate" | "resting_heart_rate" | "respiratory_rate", "count/s") => {
            (60.0, "count/min")
        }
        ("weight", "lb") => (0.45359237, "kg"),
        ("weight", "kg") => (1.0, "kg"),
        ("active_energy", "kJ") => (1.0 / 4.184, "kcal"),
        ("sleep", _) => (1.0, "category"),
        (_, "") => return None,
        (_, u) => (1.0, u),
    };
    Some((value * scale, canonical.into()))
}
#[derive(Clone, Serialize)]
struct Sample {
    id: String,
    metric: String,
    source: String,
    start_ms: i64,
    end_ms: i64,
    value: Option<f64>,
    unit: String,
    evidence_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_version: Option<String>,
}
fn sample(e: &Evidence) -> Option<Sample> {
    let v = &e.event;
    let id = v["id"].as_str()?;
    let t = v["type"].as_str()?;
    let start = v["start_ms"].as_i64()?;
    let end = v["end_ms"].as_i64()?;
    if id.len() > 200
        || t.len() > 200
        || end < start
        || start < 0
        || DateTime::from_timestamp_millis(end).is_none()
    {
        return None;
    }
    let m = metric(t);
    let (value, unit) = if m == "workout" {
        (v["duration_seconds"].as_f64(), "s".into())
    } else {
        let (n, u) = normalize(m, v["unit"].as_str().unwrap_or(""), v["value"].as_f64()?)?;
        (Some(n), u)
    };
    Some(Sample {
        id: id.into(),
        metric: m.into(),
        source: v["source"].as_str().unwrap_or("unknown").into(),
        start_ms: start,
        end_ms: end,
        value,
        unit,
        evidence_ref: e.reference.clone(),
        source_version: v["source_version"].as_str().map(str::to_owned),
    })
}
fn boundary(date: NaiveDate, tz: Tz) -> Result<i64> {
    tz.from_local_datetime(&date.and_hms_opt(0, 0, 0).unwrap())
        .earliest()
        .map(|d| d.timestamp_millis())
        .ok_or(Error::Malformed(
            "ambiguous or nonexistent local day boundary",
        ))
}
fn date(s: Option<&str>) -> Result<NaiveDate> {
    s.and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .ok_or(Error::Malformed(
            "start and end must be YYYY-MM-DD; end is exclusive",
        ))
}
fn union_ms(intervals: &mut [(i64, i64)]) -> i64 {
    intervals.sort_unstable();
    let mut total = 0;
    let mut last = None;
    for &(a, b) in intervals.iter() {
        if let Some((x, y)) = last {
            if a <= y {
                last = Some((x, y.max(b)));
            } else {
                total += y - x;
                last = Some((a, b));
            }
        } else {
            last = Some((a, b));
        }
    }
    if let Some((a, b)) = last {
        total += b - a;
    }
    total
}

pub fn analyze(rows: &[&Evidence], tool: &str, args: &Value, now: u64) -> Result<Value> {
    let tz: Tz = args["timezone"]
        .as_str()
        .unwrap_or("UTC")
        .parse()
        .map_err(|_| Error::Malformed("timezone must be an IANA timezone"))?;
    let mut deleted = BTreeSet::new();
    let mut latest: BTreeMap<String, &Evidence> = BTreeMap::new();
    let mut statuses: BTreeMap<String, &Evidence> = BTreeMap::new();
    let mut invalid = 0usize;
    for e in rows {
        if let Some(status) = e.event.get("sync_status") {
            let id = status["device_id"].as_str().unwrap_or("unknown").to_owned();
            if statuses
                .get(&id)
                .is_none_or(|old| (e.at, &e.record_id) > (old.at, &old.record_id))
            {
                statuses.insert(id, e);
            }
            continue;
        }
        let Some(id) = e.event["id"].as_str() else {
            invalid += 1;
            continue;
        };
        // HealthKit objects are immutable. A tombstone wins regardless of upload
        // order; a delayed snapshot cannot resurrect the same deleted UUID.
        if e.event["deleted"] == true {
            deleted.insert(id.to_owned());
            continue;
        }
        if latest
            .get(id)
            .is_none_or(|old| (e.at, &e.record_id) > (old.at, &old.record_id))
        {
            latest.insert(id.to_owned(), e);
        }
    }
    let mut all = Vec::new();
    for (id, e) in latest {
        if !deleted.contains(&id) {
            if let Some(s) = sample(e) {
                all.push(s)
            } else {
                invalid += 1;
            }
        }
    }
    all.sort_by(|a, b| (a.start_ms, &a.id).cmp(&(b.start_ms, &b.id)));
    let selected_metrics: Vec<&str> = args["metrics"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let matches = |s: &Sample| {
        (selected_metrics.is_empty() || selected_metrics.contains(&s.metric.as_str()))
            && args["source"]
                .as_str()
                .is_none_or(|source| source == s.source)
    };
    let mut out = json!({"schema":"hc.health.v1","content_role":"untrusted_evidence","scope":"current_grant",
        "timezone":tz.name(),"source_policy":"separate_sources","remote_sync":"not_checked",
        "invalid_records":invalid,"deletion_policy":"immutable_uuid_tombstone_wins",
        "sync_coverage":"unknown_without_current_phone_checkpoint",
        "sync_status":statuses.values().map(|e|json!({"evidence_ref":e.reference,"ingested_at_ms":e.at,"status":e.event["sync_status"]})).collect::<Vec<_>>()});
    if tool == "health_status" {
        let mut groups: BTreeMap<(String, String, String), Vec<&Sample>> = BTreeMap::new();
        for s in all.iter().filter(|s| matches(s)) {
            groups
                .entry((s.metric.clone(), s.source.clone(), s.unit.clone()))
                .or_default()
                .push(s);
        }
        out["metrics"]=json!(groups.into_iter().map(|((m,source,unit),r)|json!({"metric":m,"source":source,"unit":unit,
            "sample_count":r.len(),"earliest_sample_ms":r.iter().map(|s|s.start_ms).min(),
            "latest_sample_ms":r.iter().map(|s|s.end_ms).max(),"evidence_ref":r.last().unwrap().evidence_ref})).collect::<Vec<_>>());
        out["requested_metrics_without_samples"] = json!(selected_metrics
            .iter()
            .filter(|m| !all.iter().any(|s| matches(s) && &s.metric.as_str() == *m))
            .collect::<Vec<_>>());
        return bounded(out);
    }
    let start = date(args["start"].as_str())?;
    let end = date(args["end"].as_str())?;
    let days = (end - start).num_days();
    if !(1..=93).contains(&days) {
        return Err(Error::Malformed("health window must contain 1 to 93 days"));
    }
    let lo = boundary(start, tz)?;
    let hi = boundary(end, tz)?;
    out["start"] = json!(start.to_string());
    out["end"] = json!(end.to_string());
    let selected: Vec<_> = all
        .iter()
        .filter(|s| {
            matches(s)
                && s.start_ms < hi
                && (s.end_ms > lo || s.start_ms == s.end_ms && s.start_ms >= lo)
        })
        .collect();
    if tool == "health_samples" {
        // Diagnostics can be large and belong in health_status, not each page.
        out.as_object_mut().unwrap().remove("sync_status");
        let fingerprint = Hash::of(&serde_json::to_vec(&json!([
            start.to_string(),
            end.to_string(),
            tz.name(),
            args["source"],
            args["metrics"],
            selected
        ]))?)
        .hex();
        let mut offset = 0usize;
        if let Some(cursor) = args["cursor"].as_str() {
            let (hash, n) = cursor
                .split_once(':')
                .ok_or(Error::Malformed("invalid health cursor"))?;
            if hash != fingerprint {
                return Err(Error::Denied("health evidence changed; restart pagination"));
            }
            offset = n
                .parse()
                .map_err(|_| Error::Malformed("invalid health cursor"))?;
            if offset > selected.len() {
                return Err(Error::Malformed("invalid health cursor"));
            }
        }
        let limit = args["limit"].as_u64().unwrap_or(100).clamp(1, 200) as usize;
        let mut items = Vec::new();
        let mut bytes = out.to_string().len();
        for s in selected.iter().skip(offset).take(limit) {
            let v = serde_json::to_value(s)?;
            let n = v.to_string().len();
            if bytes + n > 56_000 {
                if items.is_empty() {
                    return Err(Error::Malformed("health sample exceeds page size"));
                }
                break;
            }
            bytes += n;
            items.push(v);
        }
        let next = offset + items.len();
        out["samples"] = json!(items);
        out["has_more"] = json!(next < selected.len());
        out["next_cursor"] = if next < selected.len() {
            json!(format!("{fingerprint}:{next}"))
        } else {
            Value::Null
        };
        return bounded(out);
    }
    if tool != "health_summary" {
        return Err(Error::Malformed("unknown health tool"));
    }
    let mut daily = Vec::new();
    for i in 0..days {
        let day = start + chrono::Duration::days(i);
        let a = boundary(day, tz)?;
        let b = boundary(day + chrono::Duration::days(1), tz)?;
        let mut groups: BTreeMap<(&str, &str, &str), Vec<&Sample>> = BTreeMap::new();
        for &s in &selected {
            // Sleep intervals split at local midnight. Other observations belong
            // to their start day; do not fabricate distributions across midnight.
            let included = if s.metric == "sleep" {
                s.start_ms < b && s.end_ms > a
            } else {
                s.start_ms >= a && s.start_ms < b
            };
            if included {
                groups
                    .entry((&s.metric, &s.source, &s.unit))
                    .or_default()
                    .push(s);
            }
        }
        let mut measures = Vec::new();
        for ((m, source, unit), r) in groups {
            let mut v = json!({"metric":m,"source":source,"unit":unit,"samples":r.len(),
                "first_sample_ms":r.iter().map(|s|s.start_ms).min(),"last_sample_ms":r.iter().map(|s|s.end_ms).max(),
                "evidence_refs":r.iter().take(3).map(|s|s.evidence_ref.clone()).collect::<Vec<_>>(),"drilldown":"health_samples"});
            if m == "sleep" {
                let mut asleep = Vec::new();
                let mut bed = Vec::new();
                let mut awake = Vec::new();
                let mut stages = BTreeMap::<i64, Vec<(i64, i64)>>::new();
                for s in &r {
                    let interval = (s.start_ms.max(a), s.end_ms.min(b));
                    match s.value.map(|v| v as i64) {
                        Some(0) => bed.push(interval),
                        Some(2) => awake.push(interval),
                        Some(n @ (1 | 3 | 4 | 5)) => {
                            asleep.push(interval);
                            stages.entry(n).or_default().push(interval);
                        }
                        _ => {}
                    }
                }
                let sum: i64 = asleep.iter().map(|(x, y)| y - x).sum();
                let duration = union_ms(&mut asleep);
                let in_bed = union_ms(&mut bed);
                let awake_duration = union_ms(&mut awake);
                let mut known = asleep.clone();
                known.extend(awake);
                let mut classified_in_bed = Vec::new();
                for &(x, y) in &known {
                    for &(u, v) in &bed {
                        if x.max(u) < y.min(v) {
                            classified_in_bed.push((x.max(u), y.min(v)));
                        }
                    }
                }
                let known = union_ms(&mut classified_in_bed);
                v["unit"] = json!("minutes");
                v["asleep"] = if asleep.is_empty() {
                    Value::Null
                } else {
                    json!(duration as f64 / 60000.0)
                };
                v["in_bed"] = if bed.is_empty() {
                    Value::Null
                } else {
                    json!(in_bed as f64 / 60000.0)
                };
                v["awake"] = if awake_duration == 0 {
                    Value::Null
                } else {
                    json!(awake_duration as f64 / 60000.0)
                };
                v["overlapping_asleep_minutes"] = json!((sum - duration) as f64 / 60000.0);
                v["unclassified_in_bed_minutes"] = if in_bed == 0 {
                    Value::Null
                } else {
                    json!((in_bed - known).max(0) as f64 / 60000.0)
                };
                v["grouping"] = json!("intervals_split_at_local_midnight");
                v["stages_minutes"] = json!(stages
                    .into_iter()
                    .map(|(n, mut ints)| (n.to_string(), union_ms(&mut ints) as f64 / 60000.0))
                    .collect::<BTreeMap<_, _>>());
            } else {
                let values: Vec<_> = r.iter().filter_map(|s| s.value).collect();
                let sum: f64 = values.iter().sum();
                let method = if matches!(m, "steps" | "active_energy" | "workout") {
                    "sum"
                } else {
                    "sample_mean"
                };
                v["method"] = json!(method);
                v["value"] = if values.is_empty() {
                    Value::Null
                } else {
                    json!(if method == "sum" {
                        sum
                    } else {
                        sum / values.len() as f64
                    })
                };
                v["min"] = values
                    .iter()
                    .copied()
                    .reduce(f64::min)
                    .map_or(Value::Null, |n| json!(n));
                v["max"] = values
                    .iter()
                    .copied()
                    .reduce(f64::max)
                    .map_or(Value::Null, |n| json!(n));
                v["crosses_day_boundary"] = json!(r.iter().any(|s| s.end_ms > b));
            }
            measures.push(v);
        }
        daily.push(
            json!({"date":day.to_string(),"partial_day":b>now as i64,"measurements":measures,
            "coverage":"observed_samples_only; absence is not zero"}),
        );
    }
    out["period"] = period(&daily);
    let baseline_days = args["baseline_days"].as_u64().unwrap_or(7);
    if baseline_days > 93 {
        return Err(Error::Malformed("baseline_days must be 0 to 93"));
    }
    if baseline_days > 0 {
        let mut previous = args.clone();
        previous["start"] =
            json!((start - chrono::Duration::days(baseline_days as i64)).to_string());
        previous["end"] = json!(start.to_string());
        previous["baseline_days"] = json!(0);
        let comparison = analyze(rows, tool, &previous, now)?;
        out["baseline"] =
            json!({"start":previous["start"],"end":previous["end"],"period":comparison["period"]});
    }
    out["days"] = json!(daily);
    out["sample_count"] = json!(selected.len());
    out["notes"] = json!([
        "Sources are separate; do not sum overlapping devices.",
        "RHR is distinct from overnight heart rate. SDNN and RMSSD are distinct HRV measures.",
        "Observed samples alone cannot prove a complete day; inspect sync_status."
    ]);
    bounded(out)
}
fn period(days: &[Value]) -> Value {
    let mut groups: BTreeMap<(String, String, String), Vec<(f64, bool)>> = BTreeMap::new();
    for day in days {
        for m in day["measurements"].as_array().into_iter().flatten() {
            let value = if m["metric"] == "sleep" {
                m["asleep"].as_f64()
            } else {
                m["value"].as_f64()
            };
            if let Some(v) = value {
                groups
                    .entry((
                        m["metric"].as_str().unwrap_or("").into(),
                        m["source"].as_str().unwrap_or("").into(),
                        m["unit"].as_str().unwrap_or("").into(),
                    ))
                    .or_default()
                    .push((v, day["partial_day"] == true));
            }
        }
    }
    json!(groups.into_iter().map(|((metric,source,unit),values)| {
        let completed:Vec<_>=values.iter().filter(|(_,partial)|!*partial).map(|(v,_)|*v).collect();
        json!({"metric":metric,"source":source,"unit":unit,"observed_days":values.len(),
            "completed_calendar_days_with_data":completed.len(),"days_without_observations":days.len()-values.len(),
            "mean_per_observed_completed_day":if completed.is_empty(){Value::Null}else{json!(completed.iter().sum::<f64>()/completed.len() as f64)},
            "sum_observed_completed_days":if matches!(metric.as_str(),"steps"|"active_energy"|"workout"){json!(completed.iter().sum::<f64>())}else{Value::Null},
            "coverage":"calendar completion does not establish source sync completeness"})
    }).collect::<Vec<_>>())
}

fn bounded(v: Value) -> Result<Value> {
    if v.to_string().len() > 64_000 {
        return Err(Error::Malformed(
            "health result too large; narrow dates, metrics or source",
        ));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(id: &str, start: &str, value: f64, t: &str, unit: &str) -> Evidence {
        let at = DateTime::parse_from_rfc3339(start)
            .unwrap()
            .timestamp_millis();
        Evidence {
            reference: format!("fixture:{id}"),
            record_id: Hash::of(id.as_bytes()).hex(),
            at: 1,
            kind: "note".into(),
            tags: vec!["health".into()],
            sensitivity: crate::grant::MEDICAL,
            event: json!({"id":id,"type":t,"start_ms":at,"end_ms":at,"source":"watch","value":value,"unit":unit}),
        }
    }
    fn window() -> Value {
        json!({"start":"2026-10-05","end":"2026-10-12","timezone":"America/Los_Angeles"})
    }
    #[test]
    fn hrv_normalizes_seconds_and_preserves_sdnn_rmssd() {
        let a = evidence(
            "one",
            "2026-10-06T02:00:00Z",
            0.050,
            "HKQuantityTypeIdentifierHeartRateVariabilitySDNN",
            "s",
        );
        let b = evidence("two", "2026-10-06T02:00:00Z", 60.0, "hrv_rmssd", "ms");
        let v = analyze(&[&a, &b], "health_summary", &window(), u64::MAX / 2).unwrap();
        let m = v["days"][0]["measurements"].as_array().unwrap();
        assert_eq!(m.len(), 2);
        assert!(m
            .iter()
            .any(|v| v["metric"] == "hrv_sdnn" && v["value"] == 50.0 && v["unit"] == "ms"));
    }
    #[test]
    fn tombstones_win_over_delayed_snapshots_and_backfills_use_measurement_time() {
        let mut a = evidence(
            "one",
            "2026-10-06T02:00:00Z",
            100.0,
            "HKQuantityTypeIdentifierStepCount",
            "count",
        );
        a.at = 50;
        let mut deletion = a.clone();
        deletion.at = 20;
        deletion.event = json!({"id":"one","deleted":true});
        let old = evidence(
            "old",
            "2023-01-01T02:00:00Z",
            999.0,
            "HKQuantityTypeIdentifierStepCount",
            "count",
        );
        let v = analyze(
            &[&a, &old, &deletion, &a],
            "health_summary",
            &window(),
            u64::MAX / 2,
        )
        .unwrap();
        assert_eq!(v["sample_count"], 0);
        assert!(v["days"][0]["measurements"].as_array().unwrap().is_empty());
    }
    #[test]
    fn sources_do_not_double_count_and_changed_cursor_is_rejected() {
        let a = evidence(
            "a",
            "2026-10-06T02:00:00Z",
            100.0,
            "HKQuantityTypeIdentifierStepCount",
            "count",
        );
        let mut b = a.clone();
        b.event["id"] = json!("b");
        b.event["source"] = json!("ring");
        let mut args = window();
        args["limit"] = json!(1);
        let v = analyze(&[&a, &b], "health_samples", &args, 1).unwrap();
        assert_eq!(v["has_more"], true);
        args["cursor"] = v["next_cursor"].clone();
        assert_eq!(
            analyze(&[&a, &b], "health_samples", &args, 1).unwrap()["samples"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(analyze(&[&a], "health_samples", &args, 1).is_err());
        let sum = analyze(&[&a, &b], "health_summary", &window(), 1).unwrap();
        assert_eq!(sum["days"][0]["measurements"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn dst_and_overlapping_sleep_are_not_fabricated_as_more_sleep() {
        let mut a = evidence(
            "a",
            "2026-11-01T07:00:00Z",
            3.0,
            "HKCategoryTypeIdentifierSleepAnalysis",
            "",
        );
        a.event["end_ms"] = json!(DateTime::parse_from_rfc3339("2026-11-01T11:00:00Z")
            .unwrap()
            .timestamp_millis());
        let mut b = a.clone();
        b.event["id"] = json!("b");
        b.event["value"] = json!(1);
        let v = analyze(
            &[&a, &b],
            "health_summary",
            &json!({"start":"2026-11-01","end":"2026-11-02","timezone":"America/Los_Angeles"}),
            1,
        )
        .unwrap();
        assert_eq!(v["days"][0]["measurements"][0]["asleep"], 240.0);
        assert_eq!(
            v["days"][0]["measurements"][0]["overlapping_asleep_minutes"],
            240.0
        );
        assert!(v["days"][0]["measurements"][0]["in_bed"].is_null());
    }
    #[test]
    fn invalid_hrv_units_and_missing_samples_remain_unknown() {
        let a = evidence(
            "a",
            "2026-10-06T02:00:00Z",
            50.0,
            "HKQuantityTypeIdentifierHeartRateVariabilitySDNN",
            "count",
        );
        let v = analyze(&[&a], "health_status", &json!({"metrics":["hrv_sdnn"]}), 1).unwrap();
        assert_eq!(v["invalid_records"], 1);
        assert_eq!(v["requested_metrics_without_samples"], json!(["hrv_sdnn"]));
    }
}
