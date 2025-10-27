#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <jsmn.h>
#include "syscall-64.h"

#define MAX_TOKENS 128
#define MAX_ARG_BUFFERS 8
#define SYMBOLIC_MEM_SIZE (64 * 1024)  // 64KB for symbolic memory
#define SYMBOLIC_MEM_BASE 0x10000000   // Default symbolic memory base
#define MAX_TRACKED_FDS 256
#define MAX_TRACKED_MMAPS 64

// Resource tracking structures
typedef struct {
    int fd;
    int syscall_num;  // Which syscall created it
} tracked_fd_t;

typedef struct {
    void *addr;
    size_t length;
} tracked_mmap_t;

typedef struct {
    long syscall_num;
    long args[MAX_SYSCALL_ARGS];
    int arg_count;
    void *symbolic_mem;
    size_t symbolic_offset;
    // Track allocated buffers for cleanup
    void *buffers[MAX_ARG_BUFFERS];
    int buffer_count;
    // Resource tracking
    tracked_fd_t fds[MAX_TRACKED_FDS];
    int fd_count;
    tracked_mmap_t mmaps[MAX_TRACKED_MMAPS];
    int mmap_count;
    int cleanup_enabled;
    int symbolic_mode;  // Whether arguments should be symbolic
} syscall_context_t;

// Helper to compare JSON token with string
static int json_equal(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && 
        (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 1;
    }
    return 0;
}

// Helper to extract string value from token
static void extract_string(const char *json, jsmntok_t *tok, char *buf, size_t buflen) {
    int len = tok->end - tok->start;
    if (len >= (int)buflen) len = buflen - 1;
    memcpy(buf, json + tok->start, len);
    buf[len] = '\0';
}

// Helper to extract long value from token
static long extract_long(const char *json, jsmntok_t *tok) {
    char buf[32];
    extract_string(json, tok, buf, sizeof(buf));
    return strtol(buf, NULL, 0); // 0 base allows hex (0x) and decimal
}

// Allocate from symbolic memory region
static void* symbolic_alloc(syscall_context_t *ctx, size_t size) {
    if (ctx->symbolic_offset + size > SYMBOLIC_MEM_SIZE) {
        fprintf(stderr, "Symbolic memory exhausted\n");
        return NULL;
    }
    
    void *ptr = (char*)ctx->symbolic_mem + ctx->symbolic_offset;
    ctx->symbolic_offset += size;
    // Align to 8 bytes
    ctx->symbolic_offset = (ctx->symbolic_offset + 7) & ~7;
    
    return ptr;
}

// Process argument based on type information
static long prepare_argument(syscall_context_t *ctx, const char *json_str, 
                             jsmntok_t *token, int arg_type) {
    switch (arg_type) {
        case ARG_NONE:
            return 0;
            
        case ARG_CHAR: {
            if (!ctx->symbolic_mode) {
                // Direct value - just extract and cast
                return (long)(char)extract_long(json_str, token);
            }
            // Symbolic mode - allocate in symbolic memory
            char *val_ptr = (char*)symbolic_alloc(ctx, sizeof(char));
            if (!val_ptr) return 0;
            *val_ptr = (char)extract_long(json_str, token);
            return (long)val_ptr;
        }
        
        case ARG_SHORT: {
            if (!ctx->symbolic_mode) {
                // Direct value - just extract and cast
                return (long)(short)extract_long(json_str, token);
            }
            // Symbolic mode - allocate in symbolic memory
            short *val_ptr = (short*)symbolic_alloc(ctx, sizeof(short));
            if (!val_ptr) return 0;
            *val_ptr = (short)extract_long(json_str, token);
            return (long)val_ptr;
        }
        
        case ARG_INT:
        case ARG_FD: {
            if (!ctx->symbolic_mode) {
                // Direct value - just extract and cast
                return (long)(int)extract_long(json_str, token);
            }
            // Symbolic mode - allocate in symbolic memory
            int *val_ptr = (int*)symbolic_alloc(ctx, sizeof(int));
            if (!val_ptr) return 0;
            *val_ptr = (int)extract_long(json_str, token);
            return (long)val_ptr;
        }
        
        case ARG_LONG:
        case ARG_LONGLONG: {
            if (!ctx->symbolic_mode) {
                // Direct value - just extract
                return extract_long(json_str, token);
            }
            // Symbolic mode - allocate in symbolic memory
            long *val_ptr = (long*)symbolic_alloc(ctx, sizeof(long));
            if (!val_ptr) return 0;
            *val_ptr = extract_long(json_str, token);
            return (long)val_ptr;
        }
        
        case ARG_PTR: {
            // Generic pointer - could be NULL or a valid address
            long val = extract_long(json_str, token);
            if (val == 0) return 0; // NULL pointer
            
            // If it looks like a size/length, allocate that much memory
            if (val > 0 && val < SYMBOLIC_MEM_SIZE / 2) {
                void *ptr;
                if (ctx->symbolic_mode) {
                    ptr = symbolic_alloc(ctx, val);
                } else {
                    ptr = malloc(val);
                }
                if (ptr) memset(ptr, 0, val);
                return (long)ptr;
            }
            return val;
        }
        
        case ARG_STR: {
            // For string arguments, we need to handle the JSON value
            if (token->type == JSMN_STRING) {
                int len = token->end - token->start;
                char *str_ptr;
                if (ctx->symbolic_mode) {
                    str_ptr = (char*)symbolic_alloc(ctx, len + 1);
                } else {
                    str_ptr = (char*)malloc(len + 1);
                }
                if (!str_ptr) return 0;
                extract_string(json_str, token, str_ptr, len + 1);
                return (long)str_ptr;
            } else {
                // Could be a numeric address or size
                long val = extract_long(json_str, token);
                if (val == 0) return 0;
                if (val > 0 && val < 4096) {
                    // Looks like a size, allocate buffer
                    char *str_ptr;
                    if (ctx->symbolic_mode) {
                        str_ptr = (char*)symbolic_alloc(ctx, val);
                    } else {
                        str_ptr = (char*)malloc(val);
                    }
                    if (str_ptr) memset(str_ptr, 0, val);
                    return (long)str_ptr;
                }
                return val;
            }
        }
        
        default:
            // Unknown type, treat as long
            return extract_long(json_str, token);
    }
}

// Parse JSON input with type awareness
int parse_syscall_input(const char *json_str, syscall_context_t *ctx) {
    jsmn_parser parser;
    jsmntok_t tokens[MAX_TOKENS];
    
    jsmn_init(&parser);
    int r = jsmn_parse(&parser, json_str, strlen(json_str), tokens, MAX_TOKENS);
    
    if (r < 0) {
        fprintf(stderr, "Failed to parse JSON: %d\n", r);
        return -1;
    }
    
    if (r < 1 || (tokens[0].type != JSMN_OBJECT && tokens[0].type != JSMN_ARRAY) ) {
        fprintf(stderr, "Root element must be an object\n");
        return -1;
    }
    
    memset(ctx->args, 0, sizeof(ctx->args));
    ctx->arg_count = 0;
    
    // Parse the JSON object
    for (int i = 1; i < r; i++) {
        if (json_equal(json_str, &tokens[i], "syscall")) {
            ctx->syscall_num = extract_long(json_str, &tokens[i + 1]);
            i++; // Skip value token
        }
        else if (json_equal(json_str, &tokens[i], "symbolic")) {
            // Check if the value is true/false
            if (tokens[i + 1].type == JSMN_PRIMITIVE) {
                char bool_val[8];
                extract_string(json_str, &tokens[i + 1], bool_val, sizeof(bool_val));
                if (strcmp(bool_val, "true") == 0) {
                    ctx->symbolic_mode = 1;
                    printf("JSON: symbolic mode enabled\n");
                } else if (strcmp(bool_val, "false") == 0) {
                    ctx->symbolic_mode = 0;
                    printf("JSON: symbolic mode disabled\n");
                }
            }
            i++; // Skip value token
        }
        else if (json_equal(json_str, &tokens[i], "args")) {
            i++; // Move to array token
            if (tokens[i].type != JSMN_ARRAY) {
                fprintf(stderr, "args must be an array\n");
                return -1;
            }
            
            int array_size = tokens[i].size;
            if (array_size > MAX_SYSCALL_ARGS) {
                fprintf(stderr, "Too many arguments (max %d)\n", MAX_SYSCALL_ARGS);
                return -1;
            }
            
            ctx->arg_count = array_size;
            
            // Get syscall type information
            const syscall_args_t *arg_types = NULL;
            if (ctx->syscall_num >= 0 && ctx->syscall_num < 548) {
                arg_types = &syscall_args_table[ctx->syscall_num];
            }
            
            i++; // Move to first array element
            
            for (int j = 0; j < array_size; j++) {
                int arg_type = ARG_LONG; // Default type
                if (arg_types) {
                    arg_type = arg_types->arg_type[j];
                }
                
                ctx->args[j] = prepare_argument(ctx, json_str, &tokens[i], arg_type);
                
                printf("  arg[%d] (type=%d): 0x%lx\n", j, arg_type, ctx->args[j]);
                i++;
            }
            i--; // Adjust because outer loop will increment
        }
    }
    
    return 0;
}

// Initialize symbolic execution context
syscall_context_t* init_syscall_context(void *symbolic_mem_base, int cleanup_enabled, int symbolic_mode) {
    syscall_context_t *ctx = calloc(1, sizeof(syscall_context_t));
    if (!ctx) return NULL;
    
    ctx->symbolic_mem = symbolic_mem_base;
    ctx->symbolic_offset = 0;
    ctx->buffer_count = 0;
    ctx->fd_count = 0;
    ctx->mmap_count = 0;
    ctx->cleanup_enabled = cleanup_enabled;
    ctx->symbolic_mode = symbolic_mode;
    
    return ctx;
}

// Track file descriptor allocation
static void track_fd(syscall_context_t *ctx, int fd, long syscall_num) {
    if (!ctx->cleanup_enabled || fd < 0) return;
    
    if (ctx->fd_count < MAX_TRACKED_FDS) {
        ctx->fds[ctx->fd_count].fd = fd;
        ctx->fds[ctx->fd_count].syscall_num = syscall_num;
        ctx->fd_count++;
        printf("  Tracked FD %d (count: %d)\n", fd, ctx->fd_count);
    } else {
        fprintf(stderr, "Warning: FD tracking table full\n");
    }
}

// Track mmap allocation
static void track_mmap(syscall_context_t *ctx, void *addr, size_t length) {
    if (!ctx->cleanup_enabled || addr == MAP_FAILED || addr == NULL) return;
    
    if (ctx->mmap_count < MAX_TRACKED_MMAPS) {
        ctx->mmaps[ctx->mmap_count].addr = addr;
        ctx->mmaps[ctx->mmap_count].length = length;
        ctx->mmap_count++;
        printf("  Tracked mmap %p (len: %zu, count: %d)\n", 
               addr, length, ctx->mmap_count);
    } else {
        fprintf(stderr, "Warning: mmap tracking table full\n");
    }
}

// Remove FD from tracking (on close)
static void untrack_fd(syscall_context_t *ctx, int fd) {
    if (!ctx->cleanup_enabled) return;
    
    for (int i = 0; i < ctx->fd_count; i++) {
        if (ctx->fds[i].fd == fd) {
            // Shift remaining entries
            for (int j = i; j < ctx->fd_count - 1; j++) {
                ctx->fds[j] = ctx->fds[j + 1];
            }
            ctx->fd_count--;
            printf("  Untracked FD %d (count: %d)\n", fd, ctx->fd_count);
            return;
        }
    }
}

// Remove mmap from tracking (on munmap)
static void untrack_mmap(syscall_context_t *ctx, void *addr) {
    if (!ctx->cleanup_enabled) return;
    
    for (int i = 0; i < ctx->mmap_count; i++) {
        if (ctx->mmaps[i].addr == addr) {
            // Shift remaining entries
            for (int j = i; j < ctx->mmap_count - 1; j++) {
                ctx->mmaps[j] = ctx->mmaps[j + 1];
            }
            ctx->mmap_count--;
            printf("  Untracked mmap %p (count: %d)\n", addr, ctx->mmap_count);
            return;
        }
    }
}

// Execute the syscall (with safety checks in real implementation)
long execute_syscall(syscall_context_t *ctx) {
    printf("Executing syscall %ld with %d args:\n", 
           ctx->syscall_num, ctx->arg_count);
    
    // Dereference integer arguments before syscall
    long deref_args[MAX_SYSCALL_ARGS];
    const syscall_args_t *arg_types = NULL;
    
    if (ctx->syscall_num >= 0 && ctx->syscall_num < 548) {
        arg_types = &syscall_args_table[ctx->syscall_num];
    }
    
    for (int i = 0; i < ctx->arg_count; i++) {
        if (arg_types && ctx->symbolic_mode) {
            int arg_type = arg_types->arg_type[i];
            switch (arg_type) {
                case ARG_CHAR:
                    // Dereference char pointer
                    deref_args[i] = (ctx->args[i] != 0) ? *(char*)ctx->args[i] : 0;
                    printf("  Deref arg[%d]: %ld (from 0x%lx)\n", 
                           i, deref_args[i], ctx->args[i]);
                    break;
                case ARG_SHORT:
                    // Dereference short pointer
                    deref_args[i] = (ctx->args[i] != 0) ? *(short*)ctx->args[i] : 0;
                    printf("  Deref arg[%d]: %ld (from 0x%lx)\n", 
                           i, deref_args[i], ctx->args[i]);
                    break;
                case ARG_INT:
                case ARG_FD:
                    // Dereference int pointer
                    deref_args[i] = (ctx->args[i] != 0) ? *(int*)ctx->args[i] : 0;
                    printf("  Deref arg[%d]: %ld (from 0x%lx)\n", 
                           i, deref_args[i], ctx->args[i]);
                    break;
                case ARG_LONG:
                case ARG_LONGLONG:
                    // Dereference long pointer
                    deref_args[i] = (ctx->args[i] != 0) ? *(long*)ctx->args[i] : 0;
                    printf("  Deref arg[%d]: %ld (from 0x%lx)\n", 
                           i, deref_args[i], ctx->args[i]);
                    break;
                default:
                    // Pass through pointers and strings as-is
                    deref_args[i] = ctx->args[i];
                    break;
            }
        } else {
            // Not symbolic mode or no type info - pass through as-is
            deref_args[i] = ctx->args[i];
        }
    }
    
    // Call syscall based on arg count
    long result;
    switch (ctx->arg_count) {
        case 0:
            result = syscall(ctx->syscall_num);
            break;
        case 1:
            result = syscall(ctx->syscall_num, deref_args[0]);
            break;
        case 2:
            result = syscall(ctx->syscall_num, deref_args[0], deref_args[1]);
            break;
        case 3:
            result = syscall(ctx->syscall_num, deref_args[0], deref_args[1], 
                          deref_args[2]);
            break;
        case 4:
            result = syscall(ctx->syscall_num, deref_args[0], deref_args[1],
                          deref_args[2], deref_args[3]);
            break;
        case 5:
            result = syscall(ctx->syscall_num, deref_args[0], deref_args[1],
                          deref_args[2], deref_args[3], deref_args[4]);
            break;
        case 6:
            result = syscall(ctx->syscall_num, deref_args[0], deref_args[1],
                          deref_args[2], deref_args[3], deref_args[4],
                          deref_args[5]);
            break;
        default:
            result = -1;
    }
    
    // Track resource allocations if enabled
    if (ctx->cleanup_enabled && result >= 0) {
        switch (ctx->syscall_num) {
            // File/socket operations that return FDs
            case 2:   // open
            case 41:  // socket
            case 42:  // accept
            case 257: // openat
            case 288: // accept4
            case 319: // memfd_create
            case 425: // io_uring_setup
                track_fd(ctx, (int)result, ctx->syscall_num);
                break;
            
            // dup operations
            case 32:  // dup
            case 33:  // dup2
            case 292: // dup3
                track_fd(ctx, (int)result, ctx->syscall_num);
                break;
            
            // pipe operations (FDs written to array)
            case 22:  // pipe
            case 293: // pipe2
                if (deref_args[0]) {
                    int *fds = (int*)deref_args[0];
                    track_fd(ctx, fds[0], ctx->syscall_num);
                    track_fd(ctx, fds[1], ctx->syscall_num);
                }
                break;
            
            // mmap
            case 9:   // mmap
                if (result != (long)MAP_FAILED) {
                    size_t length = (arg_types && ctx->arg_count > 1) ? 
                                   *(size_t*)ctx->args[1] : 0;
                    track_mmap(ctx, (void*)result, length);
                }
                break;
            
            // close
            case 3:   // close
                untrack_fd(ctx, (int)deref_args[0]);
                break;
            
            // munmap
            case 11:  // munmap
                untrack_mmap(ctx, (void*)deref_args[0]);
                break;
        }
    }
    
    return result;
}

// Cleanup all tracked resources
void cleanup_resources(syscall_context_t *ctx) {
    if (!ctx->cleanup_enabled) return;
    
    printf("\n=== Cleaning up resources ===\n");
    
    // Close all tracked file descriptors
    if (ctx->fd_count > 0) {
        printf("Closing %d file descriptor(s)...\n", ctx->fd_count);
        for (int i = 0; i < ctx->fd_count; i++) {
            printf("  Closing FD %d (from syscall %ld)\n", 
                   ctx->fds[i].fd, ctx->fds[i].syscall_num);
            close(ctx->fds[i].fd);
        }
        ctx->fd_count = 0;
    }
    
    // Unmap all tracked memory mappings
    if (ctx->mmap_count > 0) {
        printf("Unmapping %d memory region(s)...\n", ctx->mmap_count);
        for (int i = 0; i < ctx->mmap_count; i++) {
            printf("  Unmapping %p (length: %zu)\n", 
                   ctx->mmaps[i].addr, ctx->mmaps[i].length);
            munmap(ctx->mmaps[i].addr, ctx->mmaps[i].length);
        }
        ctx->mmap_count = 0;
    }
    
    printf("=== Cleanup complete ===\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input.json> [options]\n", argv[0]);
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  --cleanup            Enable resource tracking and cleanup\n");
        fprintf(stderr, "  --symbolic           Enable symbolic mode (can be overridden by JSON)\n");
        fprintf(stderr, "  --symbolic-mem ADDR  Use specified symbolic memory address\n");
        fprintf(stderr, "\nExample JSON format:\n");
        fprintf(stderr, "{\n");
        fprintf(stderr, "  \"syscall\": 1,\n");
        fprintf(stderr, "  \"args\": [1, \"Hello, world!\\n\", 14],\n");
        fprintf(stderr, "  \"symbolic\": false\n");
        fprintf(stderr, "}\n");
        return 1;
    }
    
    // Parse command line options
    int cleanup_enabled = 0;
    int symbolic_mode = 0;
    void *symbolic_mem = NULL;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--cleanup") == 0) {
            cleanup_enabled = 1;
            printf("Resource tracking and cleanup enabled\n");
        } else if (strcmp(argv[i], "--symbolic") == 0) {
            symbolic_mode = 1;
            printf("Symbolic mode enabled\n");
        } else if (strcmp(argv[i], "--symbolic-mem") == 0 && i + 1 < argc) {
            symbolic_mem = (void*)strtoul(argv[i + 1], NULL, 0);
            i++; // Skip address argument
        }
    }
    
    // Allocate symbolic memory (always needed for symbolic_alloc)
    if (!symbolic_mem) {
        symbolic_mem = (void*)SYMBOLIC_MEM_BASE;
    }
    
    // Always malloc the symbolic memory region
    void *allocated_mem = malloc(SYMBOLIC_MEM_SIZE);
    if (!allocated_mem) {
        perror("malloc symbolic memory");
        return 1;
    }
    memset(allocated_mem, 0, SYMBOLIC_MEM_SIZE);
    
    // In symbolic mode, we treat allocated_mem as if it's at symbolic_mem address
    // For non-symbolic mode, we just use it as a scratch area
    printf("Allocated symbolic memory region at: %p", allocated_mem);
    if (symbolic_mode) {
        printf(" (logical address: %p)", symbolic_mem);
    }
    printf("\n");
    
    // Read JSON file
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *json_str = malloc(fsize + 1);
    if (!json_str) {
        perror("malloc");
        fclose(fp);
        return 1;
    }
    
    fread(json_str, 1, fsize, fp);
    json_str[fsize] = '\0';
    fclose(fp);
    
    // Initialize context
    syscall_context_t *ctx = init_syscall_context(allocated_mem, cleanup_enabled, symbolic_mode);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize context\n");
        free(json_str);
        free(allocated_mem);
        return 1;
    }
    
    // Parse and execute
    if (parse_syscall_input(json_str, ctx) == 0) {
        long result = execute_syscall(ctx);
        printf("Result: %ld (0x%lx)\n", result, result);
        if (result < 0) {
            printf("Errno: %d (%s)\n", errno, strerror(errno));
        }
    } else {
        fprintf(stderr, "Failed to parse input\n");
        free(ctx);
        free(json_str);
        return 1;
    }
    
    // Cleanup
    cleanup_resources(ctx);
    free(ctx);
    free(json_str);
    free(allocated_mem);
    
    return 0;
}
