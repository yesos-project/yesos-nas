#ifndef NAS_REMOTE_H
#define NAS_REMOTE_H

#include "virtio_net.h"

// UDP 31415 / 5555 handler of the NAS product (Noise channel + command protocol).
Bool nas_remote_udp(const NetUdpDatagram* d);

#endif // NAS_REMOTE_H
