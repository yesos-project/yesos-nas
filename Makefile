# =============================================================================
# YesOS NAS - network storage appliance (the YesOS core is the `core` submodule)
#   make            build yesos.elf (core + vault + packages + NAS)
#   make run        boot it in QEMU on yesos_disk.img (serial console on stdio)
#   make test       run the test suites (QEMU, headless, on copies of the disk)
# Panel: https://127.0.0.1:8443/   WebDAV: https://127.0.0.1:8443/dav/   Exit QEMU: Ctrl-A X
# =============================================================================
PRODUCT = nas
CORE_MODULES = vault packages chacha
# The Desktop's drivers must never be linked into this product.
FORBIDDEN_SYMBOLS = hda_ audio_ display_ input_ terminal_ wav_ desktop_ surf_ files_
PRODUCT_C_SRCS = $(wildcard src/*.c)
CUSTOM_DISK = 1

include core/core.mk

# QEMU user network, forwarded to 127.0.0.1 only: NAS channel, lab telemetry,
# WebDAV over HTTP (redirects), HTTPS panel/WebDAV
QEMU_NET = -netdev user,id=net0,hostfwd=udp:127.0.0.1:31415-:31415,hostfwd=udp:127.0.0.1:5555-:5555,hostfwd=tcp:127.0.0.1:8080-:8080,hostfwd=tcp:127.0.0.1:8443-:8443,hostfwd=tcp:127.0.0.1:8088-:80 -device virtio-net-pci,netdev=net0,id=nic0

yesos_disk.img:
	python3 $(CORE)/tools/redsea_injector.py yesos_disk.img sync_curated

run: $(ELF) yesos_disk.img
	qemu-system-riscv64 $(QEMU_CPU) $(QEMU_DISK) $(QEMU_NET) -kernel $(ELF) -nographic

TESTS = test_webadmin test_vault_crypto test_webdav test_snapshots test_replication \
        test_disk_stress test_redsea_v4 test_fs_model test_crash
test: $(ELF)
	@fail=0; for t in $(TESTS); do echo "== $$t"; python3 tools/$$t.py || fail=1; done; exit $$fail

nas-status:
	python3 tools/nas_client.py status

nas-list:
	python3 tools/nas_client.py list

.PHONY: run test nas-status nas-list
