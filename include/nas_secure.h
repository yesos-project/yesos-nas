#ifndef NAS_SECURE_H
#define NAS_SECURE_H

#include "types.h"

// Secure NAS channel (Noise NK over UDP 31415). See kernel/nas_secure.c for
// the wire format.

// Loads or creates the appliance's static key (SYS/NOISE.KEY). Requires the
// entropy pool and the RedSea volume.
U0   nas_secure_init(U0);

// Prints the static public key the clients must pin.
U0   nas_secure_print_key(U0);

// Handles one UDP datagram. Returns TRUE if it belonged to the secure
// protocol; `out`/`out_len` then hold the reply to send (may be 0 bytes).
Bool nas_secure_handle_datagram(U32 src_ip, const U8* data, size_t len,
                                U8* out, size_t out_cap, size_t* out_len);

#endif // NAS_SECURE_H
