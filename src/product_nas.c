// ============================================================================
// YesOS NAS - product glue: what the NAS adds to the YesOS core. The NAS is
// only a NAS: no gateway or firewall code (that is YesOS Security).
// ============================================================================

#include "product.h"
#include "kprintf.h"
#include "virtio_net.h"
#include "rust_security.h"
#include "nas_server.h"
#include "nas_secure.h"
#include "nas_remote.h"
#include "nas_shell.h"
#include "webadmin.h"
#include "snapshot.h"

const char* const PRODUCT_NAME = "YesOS NAS";

static U0 tcp_input(const U8* packet, size_t len, size_t ip_hdr_len) {
    rust_handle_tcp(packet, len, ip_hdr_len);
}

U0 product_early_init(U0) {
}

U0 product_init(U0) {
    nas_server_init();
    nas_secure_init();
    webadmin_tls_init();
    snapshot_init();

    net_register_udp(NAS_SERVER_PORT, nas_remote_udp);  // Noise channel + commands
    net_register_udp(5555, nas_remote_udp);             // lab command port
    net_register_tcp(tcp_input);                        // WebDAV, HTTPS panel
    net_set_telemetry(TRUE);
    nas_shell_register();
}

U0 product_boot_summary(U0) {
    kprintf(" [ OK ] NAS SERVICE      : UDP %u (Noise NK) | WebDAV TCP 8080 | HTTPS admin TCP %u%s\n",
            NAS_SERVER_PORT, WEBADMIN_HTTPS_PORT, webadmin_tls_ready() ? "" : " (DISABLED)");
}

U0 product_poll(U0) {
    rust_tcp_tick();      // TCP retransmission timers
    snapshot_poll();      // automatic snapshots of share/, media/ and vault/
}
