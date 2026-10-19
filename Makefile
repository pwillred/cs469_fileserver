# CS 469 Fileserver — GNU Make, POSIX C11, optional external OpenSSL prefix.
.DEFAULT_GOAL := all
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
PYTHON ?= python3
OPENSSL_PREFIX ?=
OPENSSL ?= $(if $(strip $(OPENSSL_PREFIX)),$(OPENSSL_PREFIX)/bin/openssl,openssl)
SSL_LIBS ?= -lssl -lcrypto
CRYPTO_LIBS ?= -lcrypto
SQLITE_LIBS ?= -lsqlite3
THREAD_LIBS ?= -lpthread
PTY_LIBS ?= -lutil

# Separate internal flags preserve command-line CPPFLAGS/LDFLAGS overrides.
PROJECT_CPPFLAGS := -D_POSIX_C_SOURCE=200809L
ifneq ($(strip $(OPENSSL_PREFIX)),)
PROJECT_CPPFLAGS += -I"$(OPENSSL_PREFIX)/include"
OPENSSL_LDFLAGS := -L"$(OPENSSL_PREFIX)/lib"
endif

SANITIZE ?= 0
ifeq ($(SANITIZE),1)
BUILD_DIR := build/sanitize
PROGRAM_PREFIX := $(BUILD_DIR)/
SANITIZER_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
else
BUILD_DIR := build/normal
PROGRAM_PREFIX :=
endif

SERVER_SRC := server.c server_ops.c server_util.c server_auth.c server_replication.c password_db.c server_read_ops.c server_protocol_io.c
CLIENT_SRC := client.c client_config.c client_password.c client_transport.c client_protocol.c client_commands.c
ADMIN_SRC := admin.c password_db.c
SERVER_OBJS := $(addprefix $(BUILD_DIR)/,$(SERVER_SRC:.c=.o))
CLIENT_OBJS := $(addprefix $(BUILD_DIR)/,$(CLIENT_SRC:.c=.o))
ADMIN_OBJS := $(addprefix $(BUILD_DIR)/,$(ADMIN_SRC:.c=.o))
SERVER := $(PROGRAM_PREFIX)server
CLIENT := $(PROGRAM_PREFIX)client
ADMIN := $(PROGRAM_PREFIX)admin
TEST_DIR := $(BUILD_DIR)/tests

TEST_TARGETS := test-password-db test-client-config test-client-password \
 test-client-transport test-client-protocol test-client-commands \
 test-client-failover test-server-auth test-server-auth-faults test-server-read \
 test-server-production

.PHONY: all clean test check sanitize help $(TEST_TARGETS) test-client-integration test-two-node sanitize-two-node
all: $(SERVER) $(CLIENT) $(ADMIN)

# Production reads/authentication use the same modules as the isolated suites.
$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SSL_LIBS) $(SQLITE_LIBS) $(THREAD_LIBS) $(LDLIBS)
$(CLIENT): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SSL_LIBS) $(THREAD_LIBS) $(LDLIBS)
$(ADMIN): $(ADMIN_OBJS)
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SQLITE_LIBS) $(CRYPTO_LIBS) $(LDLIBS)

$(BUILD_DIR)/%.o: %.c Makefile
	@mkdir -p "$(@D)"
	@echo "Using custom rule for $< -> $@"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP -c $< -o $@

# These substitutions apply only to dedicated test objects, never production.
$(TEST_DIR)/client_commands_faults.o: client_commands.c tests/client_io_faults.h Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP \
	  -include tests/client_io_faults.h -Dread=client_test_read -Dwrite=client_test_write -c $< -o $@
$(TEST_DIR)/test_server_auth_faults.o: tests/test_server_auth.c Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP \
	  -DSERVER_AUTH_FAULT_TEST -c $< -o $@

$(TEST_DIR)/test_password_db: $(TEST_DIR)/test_password_db.o $(BUILD_DIR)/password_db.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SQLITE_LIBS) $(CRYPTO_LIBS) $(LDLIBS)
$(TEST_DIR)/test_client_config: $(TEST_DIR)/test_client_config.o $(BUILD_DIR)/client_config.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(TEST_DIR)/test_client_password: $(TEST_DIR)/test_client_password.o $(BUILD_DIR)/client_password.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(CRYPTO_LIBS) $(PTY_LIBS) $(LDLIBS)
$(TEST_DIR)/test_client_transport: $(TEST_DIR)/test_client_transport.o $(BUILD_DIR)/client_transport.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SSL_LIBS) $(THREAD_LIBS) $(LDLIBS)
$(TEST_DIR)/test_client_protocol: $(TEST_DIR)/test_client_protocol.o $(BUILD_DIR)/client_protocol.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(TEST_DIR)/test_client_commands: $(TEST_DIR)/test_client_commands.o $(TEST_DIR)/client_commands_faults.o \
 $(BUILD_DIR)/client_config.o $(BUILD_DIR)/client_protocol.o $(BUILD_DIR)/client_transport.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SSL_LIBS) $(THREAD_LIBS) $(LDLIBS)
$(TEST_DIR)/test_client_failover: $(TEST_DIR)/test_client_failover.o $(BUILD_DIR)/client_commands.o $(BUILD_DIR)/client_protocol.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(CRYPTO_LIBS) $(LDLIBS)
$(TEST_DIR)/test_server_auth: $(TEST_DIR)/test_server_auth.o $(BUILD_DIR)/server_auth.o $(BUILD_DIR)/password_db.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SQLITE_LIBS) $(CRYPTO_LIBS) $(THREAD_LIBS) $(LDLIBS)
$(TEST_DIR)/test_server_auth_faults: $(TEST_DIR)/test_server_auth_faults.o $(BUILD_DIR)/server_auth.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(CRYPTO_LIBS) $(LDLIBS)

test-password-db: $(TEST_DIR)/test_password_db
	./$<
test-client-config: $(TEST_DIR)/test_client_config
	./$<
test-client-password: $(TEST_DIR)/test_client_password
	./$<
test-client-transport: $(TEST_DIR)/test_client_transport
	./$<
test-client-protocol: $(TEST_DIR)/test_client_protocol
	./$<
test-client-commands: $(CLIENT) $(TEST_DIR)/test_client_commands
	$(PYTHON) tests/test_client_integration.py ./$(CLIENT) $(TEST_DIR)/test_client_commands
test-client-integration: test-client-commands
test-client-failover: $(TEST_DIR)/test_client_failover
	./$<
test-server-auth: $(TEST_DIR)/test_server_auth
	./$<
test-server-auth-faults: $(TEST_DIR)/test_server_auth_faults
	./$<


$(TEST_DIR)/server_read_ops_faults.o: server_read_ops.c tests/server_read_faults.h Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP \
	  -include tests/server_read_faults.h -Dread=read_test_read -DOPENSSL_cleanse=read_test_cleanse -c $< -o $@
$(TEST_DIR)/test_server_read_ops: $(TEST_DIR)/test_server_read_ops.o $(TEST_DIR)/server_read_ops_faults.o $(BUILD_DIR)/server_auth.o $(BUILD_DIR)/password_db.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SQLITE_LIBS) $(CRYPTO_LIBS) $(LDLIBS)
$(TEST_DIR)/server_read_fixture: $(TEST_DIR)/server_read_fixture.o $(BUILD_DIR)/server_read_ops.o $(BUILD_DIR)/server_protocol_io.o $(BUILD_DIR)/server_auth.o $(BUILD_DIR)/password_db.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SQLITE_LIBS) $(SSL_LIBS) $(THREAD_LIBS) $(LDLIBS)
test-server-read: $(TEST_DIR)/test_server_read_ops $(TEST_DIR)/server_read_fixture $(CLIENT)
	./$(TEST_DIR)/test_server_read_ops
	$(PYTHON) tests/test_server_read_integration.py $(TEST_DIR)/server_read_fixture ./$(CLIENT)

$(TEST_DIR)/server_ops_credentials.o: server_ops.c Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP \
	  -DOPENSSL_cleanse=server_credentials_test_cleanse -Dserver_protocol_io_init=server_credentials_test_io_init -c $< -o $@
$(TEST_DIR)/test_server_credentials: $(TEST_DIR)/test_server_credentials.o $(TEST_DIR)/server_ops_credentials.o \
 $(BUILD_DIR)/server_util.o $(BUILD_DIR)/server_auth.o $(BUILD_DIR)/password_db.o $(BUILD_DIR)/server_read_ops.o $(BUILD_DIR)/server_protocol_io.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SQLITE_LIBS) $(SSL_LIBS) $(THREAD_LIBS) $(LDLIBS)
$(TEST_DIR)/test_server_fields: $(TEST_DIR)/test_server_fields.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
test-server-production: $(SERVER) $(CLIENT) $(TEST_DIR)/server_read_fixture $(TEST_DIR)/test_server_fields $(TEST_DIR)/test_server_credentials
	./$(TEST_DIR)/test_server_fields
	./$(TEST_DIR)/test_server_credentials
	$(PYTHON) tests/test_server_production_integration.py ./$(SERVER) ./$(CLIENT) $(TEST_DIR)/server_read_fixture

test: $(TEST_TARGETS)
check: test
sanitize:
	$(MAKE) SANITIZE=1 test

# Production two-node acceptance remains independently runnable.
test-two-node: $(SERVER) $(CLIENT) $(ADMIN)
	OPENSSL="$(OPENSSL)" $(PYTHON) tests/test_two_node_integration.py ./$(SERVER) ./$(CLIENT) ./$(ADMIN)
sanitize-two-node:
	$(MAKE) SANITIZE=1 test-two-node

# Only generated paths, including objects from the original root-object build.
# build/ is reserved for build products; do not store runtime data there.
clean:
	rm -f server client admin $(SERVER_SRC:.c=.o) $(SERVER_SRC:.c=.d)
	rm -rf build server.dSYM client.dSYM admin.dSYM

help:
	@echo 'make [all|server|client|admin]  Build programs (default: all three)'
	@echo 'make test / check             Run all C and Python TLS/PTY suites'
	@echo 'make test-client-commands     Run command API and executable integration tests'
	@echo 'make test-server-auth-faults  Run injected authentication failure mappings'
	@echo 'make sanitize                 Run all suites in build/sanitize using ASan/UBSan'
	@echo 'make test-two-node            Run production two-process acceptance tests'
	@echo 'make sanitize-two-node        Run two-process acceptance tests using ASan/UBSan'
	@echo 'make clean                    Remove generated binaries, objects and build/'
	@echo 'Optional: OPENSSL_PREFIX=... CC=... CFLAGS=... CPPFLAGS=... LDFLAGS=... PYTHON=python3'

-include $(wildcard $(BUILD_DIR)/*.d $(TEST_DIR)/*.d)

# Dedicated production-server fault injection; root binaries are untouched.
$(TEST_DIR)/server_ops_write_faults.o: server_ops.c tests/server_write_faults.h Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP \
	  -include tests/server_write_faults.h -Dfwrite=fault_fwrite -Dferror=fault_ferror -Dfclose=fault_fclose -c $< -o $@
$(TEST_DIR)/server_replication_write_faults.o: server_replication.c tests/server_write_faults.h Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(SANITIZER_FLAGS) -MMD -MP \
	  -include tests/server_write_faults.h -Dwrite=fault_write -c $< -o $@
$(TEST_DIR)/server_write_faults: $(filter-out $(BUILD_DIR)/server_ops.o $(BUILD_DIR)/server_replication.o,$(SERVER_OBJS)) $(TEST_DIR)/server_ops_write_faults.o $(TEST_DIR)/server_replication_write_faults.o $(TEST_DIR)/server_write_faults.o
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) -o $@ $^ $(SSL_LIBS) $(SQLITE_LIBS) $(THREAD_LIBS) $(LDLIBS)
.PHONY: test-server-write-correctness
test-server-write-correctness: $(SERVER) $(CLIENT) $(ADMIN) $(TEST_DIR)/server_write_faults
	OPENSSL="$(OPENSSL)" $(PYTHON) tests/test_server_write_correctness.py ./$(SERVER) ./$(CLIENT) ./$(ADMIN) ./$(TEST_DIR)/server_write_faults

.PHONY: test-contract-boundaries
test-contract-boundaries: $(SERVER) $(CLIENT) $(ADMIN)
	OPENSSL="$(OPENSSL)" $(PYTHON) tests/test_contract_boundaries.py ./$(SERVER) ./$(CLIENT) ./$(ADMIN)
