# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

### Basic Build
```bash
cd build
cmake ..
make
bin/fluent-bit -i cpu -o stdout -f 1
```

### Development Build
```bash
cd build
cmake -DFLB_DEV=On ../
make
```

### Testing Build
```bash
cd build
cmake -DFLB_DEV=On -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On ../
make
make test
```

### Run Specific Tests
```bash
# Internal tests
./bin/flb-it-{component}  # e.g., ./bin/flb-it-sds

# Runtime/plugin tests  
./bin/flb-rt-{plugin}     # e.g., ./bin/flb-rt-out_http

# Run test by name
./bin/flb-rt-filter_kubernetes kube_core_unescaping_json
```

### Debug Builds
```bash
# With Valgrind support
cmake -DFLB_DEV=On -DFLB_VALGRIND=On ../

# With debug symbols
cmake -DFLB_DEBUG=On ../

# With sanitizers
cmake -DSANITIZE_ADDRESS=On ../
cmake -DFLB_SANITIZE_MEMORY=On ../
```

### Code Analysis
```bash
# Run comprehensive analysis
./run_code_analysis.sh

# With specific presets
TEST_PRESET=valgrind ./run_code_analysis.sh
TEST_PRESET=coverage ./run_code_analysis.sh
```

## Architecture

### Core Design
Fluent Bit uses a **single-threaded event loop with coroutines** for high-performance, non-blocking I/O. The architecture is built around three plugin types: **Input**, **Filter**, and **Output**.

### Key Components

#### 1. Engine (`flb_engine.c`)
- Event-driven architecture using Monkey HTTP server's event loop
- Coroutine-based concurrency for non-blocking operations
- Central task and event dispatching

#### 2. Plugin System
All plugins follow consistent callback patterns:
- **Input plugins**: `cb_init`, `cb_collect`, `cb_flush_buf`, `cb_exit`
- **Filter plugins**: `cb_init`, `cb_filter`, `cb_exit` 
- **Output plugins**: `cb_init`, `cb_flush`, `cb_exit`

#### 3. Data Flow
```
Input Plugin → Chunks → Router → Filter Chain → Output Plugin
```

#### 4. Storage (`flb_input_chunk.h`)
- Data organized into chunks (256KB default, 2MB max)
- Supports logs, metrics, traces, profiles, and blobs
- MessagePack serialization for efficiency
- Memory or filesystem buffering with backpressure handling

#### 5. Concurrency Model (`flb_coro.h`)
- **Cooperative multitasking**: Coroutines yield during I/O operations
- **No thread synchronization needed**: Only one coroutine active at a time
- **Performance**: Avoids thread context switching overhead

### Important Development Notes

#### Filter Plugin Limitations
Filter plugins **cannot** make asynchronous HTTP requests. For HTTP calls in filters:
```c
/* Remove async flag from upstream */
upstream->flags &= ~(FLB_IO_ASYNC);
```

#### Context State in Output Plugins
Be careful with context state in output plugins due to coroutine switching:
```c
/* BAD: Context may be modified by other coroutines */
ctx->flag = value;
ret = flb_http_do(c, &b_sent);  // Yields to other coroutines
use_value(ctx->flag);  // May have changed!

/* GOOD: Set context during init, only read afterwards */
```

#### Memory Management
Always use Fluent Bit memory functions:
- `flb_malloc()`, `flb_calloc()`, `flb_realloc()`, `flb_free()`
- Use SDS strings (`flb_sds.h`) for string processing
- Many types have specialized create/destroy functions

### Libraries and Data Formats

#### MessagePack
All internal data uses MessagePack serialization. See `filter_record_modifier` plugin for examples of manipulating MessagePack data.

#### HTTP Client
Use the built-in HTTP client (`flb_http_client.h`, `flb_upstream.h`) rather than external libraries.

#### Linked Lists
Use `mk_list.h` for linked list operations with circular linked list implementation.

### Configuration

#### Config Maps (`flb_config_map.h`)
Modern configuration API with validation and type checking:
```c
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the data format"
    },
    {0}  /* EOF */
};
```

#### Plugin Registration
```c
struct flb_output_plugin out_plugin = {
    .name         = "plugin_name",
    .description  = "Plugin description",
    .cb_init      = cb_init,
    .cb_flush     = cb_flush,
    .cb_exit      = cb_exit,
    .config_map   = config_map
};
```

### Testing

#### Development Environment
Use devcontainer or Vagrant for consistent build environment:
```bash
# Vagrant
vagrant up && vagrant ssh

# Docker devcontainer
docker run --name devcontainer-fluent-bit \
    --volume $PWD/:/workspaces/fluent-bit \
    --user $UID:$GID --tty --detach \
    fluent/fluent-bit:latest-debug
```

#### Valgrind
For memory debugging:
```bash
cmake -DFLB_DEV=On -DFLB_VALGRIND=On ../
make
valgrind ./bin/fluent-bit {args}
valgrind ./bin/flb-rt-your-test
```

## Requirements

- CMake >= 3.0
- Flex and Bison
- YAML library/headers  
- OpenSSL library/headers

### Platform-specific Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential cmake git make openssl pkg-config
sudo apt-get install libssl-dev libsasl2-dev libsystemd-dev zlib1g-dev 
sudo apt-get install flex bison libyaml-dev
```

**macOS:**
```bash
brew install bison flex openssl
```

## Plugin Development Guidelines

1. **Follow existing patterns**: Look at similar plugins for conventions
2. **Use config maps**: Implement modern configuration API
3. **Handle errors properly**: Always check return values and clean up resources
4. **Write tests**: Create both unit tests and integration tests
5. **Memory management**: Use Fluent Bit memory functions and clean up properly
6. **Documentation**: Update plugin lists in README.md and documentation

## Key File Locations

- Plugin source: `plugins/{in_,filter_,out_}*/*`
- Core engine: `src/flb_engine.c`
- HTTP client: `src/flb_http_client.c`
- Configuration: `src/flb_config.c`
- Memory management: `src/flb_mem.c`
- Headers: `include/fluent-bit/`
- Tests: Individual test binaries in `build/bin/`