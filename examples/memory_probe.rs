// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com

//! Synthetic, local-only memory regression probe. Never accepts an existing
//! brain for fixture creation. Run modes in separate processes under time -l.
use hyperconsciousness::hlc::Clock;
use hyperconsciousness::identity::Identity;
use hyperconsciousness::keyring::RuntimeKeys;
use hyperconsciousness::log::Store;
use hyperconsciousness::query::Snapshot;
use hyperconsciousness::record::Record;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).ok_or("mode: fixture|head|snapshot")?;
    let root = PathBuf::from(args.get(2).ok_or("explicit isolated directory required")?);
    if mode == "fixture" {
        if root.exists() {
            return Err("fixture directory must not exist".into());
        }
        if std::env::var("BRAINMESH_NO_KEYSTORE").as_deref() != Ok("1") {
            return Err("set BRAINMESH_NO_KEYSTORE=1 for this synthetic fixture".into());
        }
        let mib: u64 = args.get(3).ok_or("fixture size in MiB required")?.parse()?;
        if !(1..=1024).contains(&mib) {
            return Err("fixture cap is 1024 MiB".into());
        }
        let mut identity = Identity::load_or_create(&root)?;
        identity.create_brain()?;
        let store = Store::open(&root)?;
        let log = store.log_for_write(identity.device())?;
        let mut head = log.cache_head()?;
        let mut clock = Clock::new();
        let payload =
            serde_json::json!({"kind":"note", "text":"x".repeat(1024 * 1024)}).to_string();
        for _ in 0..mib {
            let record = Record::create(
                &identity.signing,
                if head.empty { 0 } else { head.seq + 1 },
                head.id,
                clock.now(),
                1,
                identity.brain_key()?,
                payload.as_bytes(),
            )?;
            log.append_new_batch(&[record], &mut head)?;
        }
        println!("synthetic fixture: {mib} records, approximately {mib} MiB");
    } else {
        let store = Store::open(&root)?;
        match mode.as_str() {
            "head" => {
                println!("authors: {}", store.heads()?.len());
            }
            "snapshot" => {
                let identity = Identity::load_existing_for_brain(&root)?;
                let keys = RuntimeKeys::open_read_only(&root, &identity)?;
                assert!(
                    Snapshot::build(&store, &keys)?.is_none(),
                    "large snapshot must fall back"
                );
                println!("oversized snapshot correctly fell back to streaming");
            }
            _ => return Err("unknown probe mode".into()),
        }
    }
    Ok(())
}
