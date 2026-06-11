//! End-to-end demonstration of a messenger's storage lifecycle:
//!
//! 1. Create container with hardware-tuned Argon2 params + padding.
//! 2. Create a main user space.
//! 3. Add contacts (KV namespace).
//! 4. Send + receive messages (log namespace, batched).
//! 5. Update settings.
//! 6. Reopen the container — auto-vacuum scrubs orphan IndexNodes.
//! 7. Periodic compaction — physically eliminates deleted entries.
//! 8. Hidden second space (deniability demo).
//!
//! Run with: `cargo run --example messenger_lifecycle`

use hidden_volume::Container;
use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::space::log::log_id_key;

fn main() -> hidden_volume::Result<()> {
    let path = std::env::temp_dir().join("hv_messenger_demo.store");
    let _ = std::fs::remove_file(&path);

    println!("== Step 1: create container ==");
    let options = ContainerOptions {
        // MIN params for fast demo; production use DEFAULT or HEAVY.
        argon2: Argon2Params::MIN,
        // Decoy size — file appears to be ~2 MiB on disk regardless of
        // actual content.
        initial_garbage_chunks: 512,
        // Quantize file growth in 1 MiB buckets.
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 256 },
        superblock_replicas: 3,
    };
    {
        let _ = Container::create_with_options(&path, options)?;
    } // close to release lock

    println!("== Step 2: open + create main user space ==");
    let main_password = b"correct horse battery staple";
    {
        let mut container = Container::open(&path)?;
        let mut space = container.create_space(main_password)?;

        println!("== Step 3: add contacts ==");
        let mut tx = space.begin_tx();
        for (id, email) in [
            ("alice", "alice@example.com"),
            ("bob", "bob@example.com"),
            ("carol", "carol@example.com"),
        ] {
            tx.put(Namespace::CONTACTS, id.as_bytes(), email.as_bytes())?;
        }
        tx.commit()?;
        println!("   {} contacts stored", space.count(Namespace::CONTACTS)?);

        println!("== Step 4: send + receive 50 messages in 5 batches ==");
        let mut next_msg_id: u64 = 1;
        for batch_idx in 0..5 {
            let mut tx = space.begin_tx();
            for _ in 0..10 {
                let payload = format!("message #{next_msg_id} from batch {batch_idx}");
                tx.append_log(Namespace::MESSAGE_LOG, next_msg_id, payload.as_bytes())?;
                next_msg_id += 1;
            }
            tx.commit()?;
        }
        println!(
            "   {} messages stored across {} commit batches",
            space.count(Namespace::MESSAGE_LOG)?,
            5
        );

        println!("== Step 5: update settings ==");
        let mut tx = space.begin_tx();
        tx.put(Namespace::SETTINGS, b"theme", b"dark")?;
        tx.put(Namespace::SETTINGS, b"language", b"en")?;
        tx.commit()?;

        println!("== Step 5a: delete a contact + a message ==");
        let mut tx = space.begin_tx();
        tx.delete(Namespace::CONTACTS, b"bob")?;
        tx.delete(Namespace::MESSAGE_LOG, &log_id_key(7))?;
        tx.commit()?;
        println!(
            "   after delete: {} contacts, {} messages",
            space.count(Namespace::CONTACTS)?,
            space.count(Namespace::MESSAGE_LOG)?
        );
    }

    println!("== Step 6: reopen → auto-vacuum scrubs orphan IndexNodes ==");
    {
        let mut container = Container::open(&path)?;
        // Set padding/replica policy on reopen (runtime config).
        container
            .set_padding_policy(PaddingPolicy::BucketGrowth { bucket_chunks: 256 })
            .unwrap();
        container.set_superblock_replicas(3).unwrap();
        let mut space = container.open_space(main_password)?;
        println!("   commit_seq after reopen = {}", space.commit_seq());
        println!(
            "   alice still in contacts: {}",
            space.get(Namespace::CONTACTS, b"alice")?.is_some()
        );
        println!(
            "   bob deleted: {}",
            space.get(Namespace::CONTACTS, b"bob")?.is_none()
        );
        println!(
            "   message #1 readable: {}",
            space.read_log(Namespace::MESSAGE_LOG, 1)?.is_some()
        );
        println!(
            "   message #7 deleted: {}",
            space.read_log(Namespace::MESSAGE_LOG, 7)?.is_none()
        );
    }

    let size_before_compact = std::fs::metadata(&path)?.len();
    println!(
        "== Step 7: file size before compact: {} bytes ==",
        size_before_compact
    );

    println!("== Step 7a: hidden second space (deniability demo) ==");
    let hidden_password = b"my real identity";
    {
        let mut container = Container::open(&path)?;
        let mut space = container.create_space(hidden_password)?;
        let mut tx = space.begin_tx();
        tx.put(
            Namespace::SETTINGS,
            b"username",
            b"my real identity behind the cover",
        )?;
        tx.append_log(
            Namespace::MESSAGE_LOG,
            1,
            b"this message is in a hidden space",
        )?;
        tx.commit()?;
    }

    println!("== Step 7b: compact_known with BOTH passwords (full vacuum) ==");
    let opts = RepackOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 512,
        padding_policy: PaddingPolicy::BucketGrowth { bucket_chunks: 256 },
        superblock_replicas: 3,
    };
    Container::compact_known(&path, &[main_password, hidden_password], opts)?;

    let size_after_compact = std::fs::metadata(&path)?.len();
    println!(
        "   file size after compact: {} bytes (delta: {})",
        size_after_compact,
        size_after_compact as i64 - size_before_compact as i64
    );

    println!("== Step 8: verify both spaces survived compact ==");
    {
        let mut container = Container::open(&path)?;
        {
            let mut main = container.open_space(main_password)?;
            println!(
                "   main: {} contacts, {} messages, theme={:?}",
                main.count(Namespace::CONTACTS)?,
                main.count(Namespace::MESSAGE_LOG)?,
                main.get(Namespace::SETTINGS, b"theme")?
                    .map(|v| String::from_utf8_lossy(&v).into_owned()),
            );
        }
        {
            let mut hidden = container.open_space(hidden_password)?;
            println!(
                "   hidden: username={:?}",
                hidden
                    .get(Namespace::SETTINGS, b"username")?
                    .map(|v| String::from_utf8_lossy(&v).into_owned()),
            );
        }
    }

    println!("\nDemo complete. File: {}", path.display());
    println!("Cleaning up...");
    let _ = std::fs::remove_file(&path);
    Ok(())
}
