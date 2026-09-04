//! Single-instance guard via the session bus.
//!
//! The first process claims the name `me.kavishdevar.librepods` (same string as the
//! Wayland app id) and serves `org.freedesktop.Application`. A later launch sees the
//! name is taken, calls `Activate` to raise the running window, then exits. Same idea
//! as GTK's GApplication.
//!
//! This is not XDG D-Bus activation: we never need the bus to launch us, only to spot
//! an instance that's already up.

use crate::ui::messages::BluetoothUIMessage;
use dbus::arg::{PropMap, RefArg, Variant};
use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply;
use dbus_crossroads::{Crossroads, IfaceBuilder};
use log::{error, info, warn};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

const BUS_NAME: &str = "me.kavishdevar.librepods";
const OBJ_PATH: &str = "/me/kavishdevar/librepods";
const APP_IFACE: &str = "org.freedesktop.Application";

pub enum InstanceRole {
    /// We own the name; we are the running application.
    Primary,
    /// Another instance already owns the name; the caller should exit.
    Secondary,
}

/// Try to claim the name. Returns `Primary` if we got it (a background thread then
/// serves the interface until the process exits), or `Secondary` if someone else
/// owns it, in which case the caller should exit. When `raise_existing` is set, a
/// secondary asks the primary to raise its window first.
///
/// If the session bus isn't reachable, we just run as `Primary` without the guard
/// rather than refusing to start.
pub fn acquire(ui_tx: UnboundedSender<BluetoothUIMessage>, raise_existing: bool) -> InstanceRole {
    let (role_tx, role_rx) = std::sync::mpsc::channel::<InstanceRole>();

    let spawned = std::thread::Builder::new()
        .name("dbus-single-instance".into())
        .spawn(move || {
            let conn = match Connection::new_session() {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Session D-Bus unavailable, single-instance disabled: {e}");
                    let _ = role_tx.send(InstanceRole::Primary);
                    return;
                }
            };

            // do_not_queue: answer now (primary or exists), don't sit in the queue.
            match conn.request_name(BUS_NAME, false, true, true) {
                Ok(RequestNameReply::PrimaryOwner) | Ok(RequestNameReply::AlreadyOwner) => {
                    info!("Acquired single-instance name {BUS_NAME} (primary)");
                    let _ = role_tx.send(InstanceRole::Primary);
                    serve(conn, ui_tx); // blocks until the process exits
                }
                Ok(RequestNameReply::Exists) | Ok(RequestNameReply::InQueue) => {
                    info!("Another LibrePods instance owns {BUS_NAME} (secondary)");
                    if raise_existing {
                        if let Err(e) = activate_existing(&conn) {
                            warn!("Failed to raise existing instance: {e}");
                        }
                    }
                    let _ = role_tx.send(InstanceRole::Secondary);
                }
                Err(e) => {
                    warn!("request_name failed, single-instance disabled: {e}");
                    let _ = role_tx.send(InstanceRole::Primary);
                }
            }
        });

    if spawned.is_err() {
        warn!("Could not spawn single-instance thread; continuing without it");
        return InstanceRole::Primary;
    }

    role_rx.recv().unwrap_or(InstanceRole::Primary)
}

/// Ask the running instance to raise/open its main window.
fn activate_existing(conn: &Connection) -> Result<(), dbus::Error> {
    let proxy = conn.with_proxy(BUS_NAME, OBJ_PATH, Duration::from_millis(2000));
    let platform_data = PropMap::new();
    let () = proxy.method_call(APP_IFACE, "Activate", (platform_data,))?;
    Ok(())
}

/// Serve `org.freedesktop.Application`. Activate and Open both just raise the window;
/// the URI and action arguments are ignored, since there's nothing else to route
/// them to.
fn serve(conn: Connection, ui_tx: UnboundedSender<BluetoothUIMessage>) {
    let mut cr = Crossroads::new();

    let token = cr.register(APP_IFACE, |b: &mut IfaceBuilder<()>| {
        let tx = ui_tx.clone();
        b.method(
            "Activate",
            ("platform_data",),
            (),
            move |_ctx, _data, (_platform_data,): (PropMap,)| {
                let _ = tx.send(BluetoothUIMessage::OpenWindow);
                Ok(())
            },
        );

        let tx = ui_tx.clone();
        b.method(
            "Open",
            ("uris", "platform_data"),
            (),
            move |_ctx, _data, (_uris, _platform_data): (Vec<String>, PropMap)| {
                let _ = tx.send(BluetoothUIMessage::OpenWindow);
                Ok(())
            },
        );

        b.method(
            "ActivateAction",
            ("action_name", "parameter", "platform_data"),
            (),
            move |_ctx,
                  _data,
                  (_action, _parameter, _platform_data): (
                String,
                Vec<Variant<Box<dyn RefArg>>>,
                PropMap,
            )| { Ok(()) },
        );
    });

    cr.insert(OBJ_PATH, &[token], ());

    if let Err(e) = cr.serve(&conn) {
        error!("Single-instance D-Bus server stopped: {e}");
    }
}
