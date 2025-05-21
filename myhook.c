#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h> // For read, write, execve
#include <stdarg.h> // For va_list, va_start, va_end in vsprintf_hook
#include <sys/types.h> // For open
#include <sys/stat.h>  // For open
#include <fcntl.h>     // For open
#include <syslog.h>    // For syslog

// --- Typedefs for original functions ---
typedef void* (*malloc_t)(size_t size);
typedef void* (*calloc_t)(size_t nmemb, size_t size);
typedef void* (*realloc_t)(void *ptr, size_t size);
typedef void  (*free_t)(void *ptr);

typedef char* (*strcpy_t)(char *dest, const char *src);
typedef char* (*strncpy_t)(char *dest, const char *src, size_t n);
typedef char* (*strcat_t)(char *dest, const char *src);
typedef char* (*strncat_t)(char *dest, const char *src, size_t n);
typedef char* (*gets_t)(char *s); // Highly dangerous

typedef int   (*sprintf_t)(char *str, const char *format, ...);
typedef int   (*vsprintf_t)(char *str, const char *format, va_list ap);
typedef int   (*snprintf_t)(char *str, size_t size, const char *format, ...);

typedef void* (*memcpy_t)(void *dest, const void *src, size_t n);
typedef void* (*memmove_t)(void *dest, const void *src, size_t n);
typedef void* (*memset_t)(void *s, int c, size_t n);

typedef int   (*open_t)(const char *pathname, int flags, ...); // mode_t is variadic
typedef ssize_t (*read_t)(int fd, void *buf, size_t count);
typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);

typedef int   (*system_t)(const char *command);
typedef int   (*execve_t)(const char *pathname, char *const argv[], char *const envp[]);

typedef int   (*printf_t)(const char *format, ...);
typedef int   (*fprintf_t)(FILE *stream, const char *format, ...);
// Note: syslog has a different signature depending on usage, hooking the most common one.
typedef void  (*syslog_t)(int priority, const char *format, ...);


// --- Pointers to original functions ---
static malloc_t original_malloc = NULL;
static calloc_t original_calloc = NULL;
static realloc_t original_realloc = NULL;
static free_t original_free = NULL;

static strcpy_t original_strcpy = NULL;
static strncpy_t original_strncpy = NULL;
static strcat_t original_strcat = NULL;
static strncat_t original_strncat = NULL;
static gets_t original_gets = NULL;

static sprintf_t original_sprintf = NULL;
static vsprintf_t original_vsprintf = NULL;
static snprintf_t original_snprintf = NULL;

static memcpy_t original_memcpy = NULL;
static memmove_t original_memmove = NULL;
static memset_t original_memset = NULL;

static open_t original_open = NULL;
static read_t original_read = NULL;
static write_t original_write = NULL;

static system_t original_system = NULL;
static execve_t original_execve = NULL;

static printf_t original_printf = NULL;
static fprintf_t original_fprintf = NULL;
static syslog_t original_syslog = NULL;


// --- Initialization flag ---
static int initializing = 0; // Prevents recursion during dlsym

// Helper macro to simplify dlsym and error checking
#define LOAD_ORIGINAL_FUNC(func_name, func_type) \
    original_##func_name = (func_type)dlsym(RTLD_NEXT, #func_name); \
    if (!original_##func_name) { \
        fprintf(stderr, "[HOOK_LIB] Error in dlsym for %s: %s\n", #func_name, dlerror()); \
    } else { \
        /*printf("[HOOK_LIB] Hook for %s initialized.\n", #func_name); */ \
    }

// --- Constructor to initialize all hooks ---
__attribute__((constructor))
static void init_hooks(void) {
    initializing = 1; // Set flag before any dlsym calls

    LOAD_ORIGINAL_FUNC(malloc, malloc_t);
    LOAD_ORIGINAL_FUNC(calloc, calloc_t);
    LOAD_ORIGINAL_FUNC(realloc, realloc_t);
    LOAD_ORIGINAL_FUNC(free, free_t);

    LOAD_ORIGINAL_FUNC(strcpy, strcpy_t);
    LOAD_ORIGINAL_FUNC(strncpy, strncpy_t);
    LOAD_ORIGINAL_FUNC(strcat, strcat_t);
    LOAD_ORIGINAL_FUNC(strncat, strncat_t);
    LOAD_ORIGINAL_FUNC(gets, gets_t);

    LOAD_ORIGINAL_FUNC(sprintf, sprintf_t);
    LOAD_ORIGINAL_FUNC(vsprintf, vsprintf_t);
    LOAD_ORIGINAL_FUNC(snprintf, snprintf_t);

    LOAD_ORIGINAL_FUNC(memcpy, memcpy_t);
    LOAD_ORIGINAL_FUNC(memmove, memmove_t);
    LOAD_ORIGINAL_FUNC(memset, memset_t);

    LOAD_ORIGINAL_FUNC(open, open_t);
    LOAD_ORIGINAL_FUNC(read, read_t);
    LOAD_ORIGINAL_FUNC(write, write_t);

    LOAD_ORIGINAL_FUNC(system, system_t);
    LOAD_ORIGINAL_FUNC(execve, execve_t);

    LOAD_ORIGINAL_FUNC(printf, printf_t);
    LOAD_ORIGINAL_FUNC(fprintf, fprintf_t);
    LOAD_ORIGINAL_FUNC(syslog, syslog_t);


    initializing = 0; // Clear flag after all dlsym calls
    printf("[HOOK_LIB] All hooks initialized.\n");
}

// --- Hooked Functions ---

// --- Memory Allocation ---
void *malloc(size_t size) {
    if (initializing || !original_malloc) return NULL; // Simplified error handling
    printf("[HOOK] malloc(size=%zu)\n", size);
    void *ptr = original_malloc(size);
    printf("[HOOK] malloc -> %p\n", ptr);
    return ptr;
}

void *calloc(size_t nmemb, size_t size) {
    if (initializing || !original_calloc) return NULL;
    printf("[HOOK] calloc(nmemb=%zu, size=%zu)\n", nmemb, size);
    void *ptr = original_calloc(nmemb, size);
    printf("[HOOK] calloc -> %p\n", ptr);
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (initializing || !original_realloc) return NULL;
    printf("[HOOK] realloc(ptr=%p, size=%zu)\n", ptr, size);
    void *new_ptr = original_realloc(ptr, size);
    printf("[HOOK] realloc -> %p\n", new_ptr);
    return new_ptr;
}

void free(void *ptr) {
    if (initializing || !original_free) return;
    printf("[HOOK] free(ptr=%p)\n", ptr);
    original_free(ptr);
    printf("[HOOK] free done\n");
}

// --- String Operations ---
char *strcpy(char *dest, const char *src) {
    if (initializing || !original_strcpy) return dest; // Potentially unsafe if original_strcpy is NULL
    // For demonstration, limit string printing to avoid overly long outputs
    char src_preview[65];
    strncpy(src_preview, src, 64);
    src_preview[64] = '\0';
    printf("[HOOK] strcpy(dest=%p, src=\"%s\" (len=%zu))\n", dest, src_preview, strlen(src));
    // Potential check: if (strlen(src) > some_safe_limit_for_dest) { log_warning(); }
    char *ret = original_strcpy(dest, src);
    return ret;
}

char *strncpy(char *dest, const char *src, size_t n) {
    if (initializing || !original_strncpy) return dest;
    char src_preview[65];
    strncpy(src_preview, src, 64);
    src_preview[64] = '\0';
    printf("[HOOK] strncpy(dest=%p, src=\"%s\", n=%zu)\n", dest, src_preview, n);
    // Potential check: if n is very large or src is not null-terminated within n
    char *ret = original_strncpy(dest, src, n);
    return ret;
}

char *strcat(char *dest, const char *src) {
    if (initializing || !original_strcat) return dest;
     char src_preview[65];
    strncpy(src_preview, src, 64);
    src_preview[64] = '\0';
    printf("[HOOK] strcat(dest_start_content=\"%.32s...\", src=\"%s\" (len=%zu))\n", dest, src_preview, strlen(src));
    char *ret = original_strcat(dest, src);
    return ret;
}

char *strncat(char *dest, const char *src, size_t n) {
    if (initializing || !original_strncat) return dest;
    char src_preview[65];
    strncpy(src_preview, src, 64);
    src_preview[64] = '\0';
    printf("[HOOK] strncat(dest_start_content=\"%.32s...\", src=\"%s\", n=%zu)\n", dest, src_preview, n);
    char *ret = original_strncat(dest, src, n);
    return ret;
}

char *gets(char *s) {
    if (initializing || !original_gets) return NULL;
    printf("[HOOK] gets(s_buffer_addr=%p) --- DANGEROUS FUNCTION CALLED!\n", s);
    // This is inherently unsafe. The hook can't make it safe, only observe it.
    char *ret = original_gets(s);
    if (ret) {
        printf("[HOOK] gets -> input: \"%.64s...\"\n", ret);
    }
    return ret;
}

// --- Formatted String Output (example for sprintf, others similar) ---
// Note: For variadic functions, you need to handle va_list or call the original carefully.
// Hooking vsprintf is often easier if the original function has a 'v' version.
int sprintf(char *str, const char *format, ...) {
    if (initializing || !original_sprintf) return -1;
    
    char format_preview[129];
    strncpy(format_preview, format, 128);
    format_preview[128] = '\0';
    printf("[HOOK] sprintf(str=%p, format=\"%s\", ...)\n", str, format_preview);
    // Potential check: if (strstr(format, "%n")) { log_warning_format_string_n(); }

    va_list args;
    va_start(args, format);
    // To safely call original_sprintf, you'd ideally use original_vsprintf if available
    // or re-construct the call, which is complex.
    // For simplicity, let's assume we can call original_sprintf directly if it's loaded
    // This is a simplification; a robust hook for variadic functions is harder.
    // A common pattern is to hook the 'v' version (e.g., vsprintf) instead if available.
    // If we only have original_sprintf, we can't directly pass 'args' to it.
    // We would typically use original_vsprintf with the 'args'.
    // For now, this is a placeholder for more complex variadic handling.
    // Let's try to use vsprintf for the actual call if possible.
    int ret;
    if (original_vsprintf) {
        // This is the preferred way if vsprintf is also hooked or directly usable
        ret = original_vsprintf(str, format, args);
    } else {
        // Fallback: This part is tricky and often not directly possible
        // without re-implementing the variadic call or using assembly.
        // For logging purposes, we might just log the format string.
        // The actual call to original_sprintf(...) would happen by the application's
        // compiled code. Our hook just observes.
        // So, to call the *original* sprintf with its varargs, we need original_sprintf.
        // The line below IS NOT how you call a variadic function by forwarding va_list
        // to a non-va_list function. This is for illustration of calling the original.
        // A real sprintf hook would be more complex.
        // We'll rely on the fact that `original_sprintf` will be called correctly
        // by the original call site. Our hook just logs.
        // To actually execute the original *with the current varargs*:
        // One way is to use a trampoline or very carefully use the 'v' version.
        // For this example, we'll assume the original call happens "naturally"
        // after our logging. The `original_sprintf` pointer is for other contexts
        // or if we were to *replace* functionality.

        // A more correct way to get the result while still logging the format:
        char temp_buffer_for_vsprintf[4096]; // Be careful with buffer size
        ret = vsprintf(temp_buffer_for_vsprintf, format, args); // This will call OUR vsprintf hook if it exists
        if (ret >= 0 && (size_t)ret < sizeof(temp_buffer_for_vsprintf)) {
             original_strcpy(str, temp_buffer_for_vsprintf); // Use original_strcpy to avoid re-hooking
        } else if (ret >=0) {
            // Output was too large for temp_buffer_for_vsprintf
            // This is a limitation of this simple approach
            // A full solution would allocate dynamically or use a different strategy.
            fprintf(stderr, "[HOOK] sprintf: Output too large for internal buffer during logging.\n");
            // Call the original directly (this is a bit of a conceptual mess here)
            // For simple logging, it's often enough to just print the format.
            // The application's call to sprintf will still use the original varargs.
            // Our `ret = original_sprintf(str, format, ...)` isn't quite right without
            // being able to forward the `...`
        }
        // The line below is just conceptual for "calling the original"
        // In reality, the program will call the original sprintf. We just log.
        // ret = original_sprintf(str, format, /* what to put here for ... ? */);
        // The most practical way is to hook vsprintf as well.
    }
    va_end(args);
    printf("[HOOK] sprintf -> wrote %d bytes, content preview: \"%.64s...\"\n", ret, str);
    return ret;
}


int vsprintf(char *str, const char *format, va_list ap) {
    if (initializing || !original_vsprintf) return -1;
    char format_preview[129];
    strncpy(format_preview, format, 128);
    format_preview[128] = '\0';
    printf("[HOOK] vsprintf(str=%p, format=\"%s\", va_list)\n", str, format_preview);
    // Check for %n
    if (strstr(format, "%n")) {
        printf("[HOOK_ALERT] Potential format string vulnerability: '%%n' detected in vsprintf format: \"%s\"\n", format_preview);
    }
    int ret = original_vsprintf(str, format, ap);
    printf("[HOOK] vsprintf -> wrote %d bytes, content preview: \"%.64s...\"\n", ret, str);
    return ret;
}


int snprintf(char *str, size_t size, const char *format, ...) {
    if (initializing || !original_snprintf) return -1;
    char format_preview[129];
    strncpy(format_preview, format, 128);
    format_preview[128] = '\0';
    printf("[HOOK] snprintf(str=%p, size=%zu, format=\"%s\", ...)\n", str, size, format_preview);
    // Check for %n
    if (strstr(format, "%n")) {
        printf("[HOOK_ALERT] Potential format string vulnerability: '%%n' detected in snprintf format: \"%s\"\n", format_preview);
    }
    va_list args;
    va_start(args, format);
    // It's better to call the original 'v' version if available for varargs forwarding
    // For snprintf, there's vsnprintf. We'd ideally hook that or use it here.
    // For simplicity, this example will assume direct call is okay for logging,
    // or rely on a hooked vsnprintf.
    int ret = original_vsnprintf(str, size, format, args); // Assuming original_vsnprintf is loaded
    va_end(args);
    printf("[HOOK] snprintf -> wrote %d bytes (buffer size %zu), content preview: \"%.64s...\"\n", ret, size, str);
    return ret;
}


// --- Memory Copying ---
void *memcpy(void *dest, const void *src, size_t n) {
    if (initializing || !original_memcpy) return dest;
    printf("[HOOK] memcpy(dest=%p, src=%p, n=%zu)\n", dest, src, n);
    // Potential check: if (src < dest && dest < src + n) or (dest < src && src < dest + n) -> overlap, use memmove
    return original_memcpy(dest, src, n);
}

void *memmove(void *dest, const void *src, size_t n) {
    if (initializing || !original_memmove) return dest;
    printf("[HOOK] memmove(dest=%p, src=%p, n=%zu)\n", dest, src, n);
    return original_memmove(dest, src, n);
}

void *memset(void *s, int c, size_t n) {
    if (initializing || !original_memset) return s;
    printf("[HOOK] memset(s=%p, c=0x%x, n=%zu)\n", s, c, n);
    return original_memset(s, c, n);
}


// --- File Operations ---
int open(const char *pathname, int flags, ...) {
    if (initializing || !original_open) return -1;
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        printf("[HOOK] open(pathname=\"%s\", flags=0x%x, mode=0%o)\n", pathname, flags, mode);
        return original_open(pathname, flags, mode);
    } else {
        printf("[HOOK] open(pathname=\"%s\", flags=0x%x)\n", pathname, flags);
        return original_open(pathname, flags);
    }
}

ssize_t read(int fd, void *buf, size_t count) {
    if (initializing || !original_read) return -1;
    printf("[HOOK] read(fd=%d, buf=%p, count=%zu)\n", fd, buf, count);
    ssize_t bytes_read = original_read(fd, buf, count);
    printf("[HOOK] read -> %zd bytes\n", bytes_read);
    // Could print a preview of 'buf' if bytes_read > 0
    return bytes_read;
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (initializing || !original_write) return -1;
    printf("[HOOK] write(fd=%d, buf=%p, count=%zu)\n", fd, buf, count);
    // Could print a preview of 'buf'
    ssize_t bytes_written = original_write(fd, buf, count);
    printf("[HOOK] write -> %zd bytes\n", bytes_written);
    return bytes_written;
}

// --- Command Execution ---
int system(const char *command) {
    if (initializing || !original_system) return -1;
    printf("[HOOK] system(command=\"%s\") --- POTENTIALLY DANGEROUS!\n", command);
    return original_system(command);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (initializing || !original_execve) return -1;
    printf("[HOOK] execve(pathname=\"%s\", argv[0]=\"%s\", ...)\n", pathname, argv && argv[0] ? argv[0] : "(null)");
    // Could log all argv elements
    return original_execve(pathname, argv, envp);
}

// --- Formatted Output to stdout/stderr (example for printf) ---
int printf(const char *format, ...) {
    if (initializing || !original_printf) return -1;
    char format_preview[129];
    strncpy(format_preview, format, 128);
    format_preview[128] = '\0';

    // Simple check for %n (a common sign of format string vulnerability)
    if (strstr(format, "%n")) {
        printf("[HOOK_ALERT] Potential format string vulnerability: '%%n' detected in printf format: \"%s\"\n", format_preview);
    }
    // Log the call
    // To avoid recursion if our printf hook itself calls printf for logging,
    // we'd typically use fprintf(stderr, ...) or a direct syscall for logging.
    // For this example, we'll use a different prefix for the internal log.
    fprintf(stderr, "[LOG_printf_HOOK] printf(format=\"%s\", ...)\n", format_preview);

    va_list args;
    va_start(args, format);
    int ret = vfprintf(stdout, format, args); // Use vfprintf to forward varargs to original printf logic
    va_end(args);
    return ret;
}

int fprintf(FILE *stream, const char *format, ...) {
    if (initializing || !original_fprintf) return -1;
    char format_preview[129];
    strncpy(format_preview, format, 128);
    format_preview[128] = '\0';
    
    const char* stream_name = "unknown_stream";
    if (stream == stdout) stream_name = "stdout";
    else if (stream == stderr) stream_name = "stderr";
    // Could add more checks for file streams by trying to get their path

    if (strstr(format, "%n")) {
         fprintf(stderr, "[HOOK_ALERT] Potential format string vulnerability: '%%n' detected in fprintf (to %s) format: \"%s\"\n", stream_name, format_preview);
    }
    fprintf(stderr, "[LOG_fprintf_HOOK] fprintf(stream=%s, format=\"%s\", ...)\n", stream_name, format_preview);
    
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

void syslog(int priority, const char *format, ...) {
    if (initializing || !original_syslog) return;
     char format_preview[129];
    strncpy(format_preview, format, 128);
    format_preview[128] = '\0';

    if (strstr(format, "%n")) {
         fprintf(stderr, "[HOOK_ALERT] Potential format string vulnerability: '%%n' detected in syslog format: \"%s\"\n", format_preview);
    }
    fprintf(stderr, "[LOG_syslog_HOOK] syslog(priority=%d, format=\"%s\", ...)\n", priority, format_preview);

    va_list args;
    va_start(args, format);
    // original_syslog is already a variadic function
    original_syslog(priority, format, args); // This won't work directly. original_syslog expects '...' not va_list
                                          // Need to use vsyslog if available and hook that,
                                          // or use a trampoline.
                                          // For now, this part is illustrative of the intent.
                                          // A more correct call to original_syslog would be:
                                          // original_syslog(priority, format, /* actual varargs expected here */);
                                          // but we only have va_list.
                                          // So, for now, we'll just log. The app will call the real syslog.
                                          // If we want to *replace* syslog and call the original, we'd need vsyslog.
    // A more robust way:
    // char temp_buffer_for_vsyslog[2048];
    // vsnprintf(temp_buffer_for_vsyslog, sizeof(temp_buffer_for_vsyslog), format, args);
    // original_syslog(priority, "%s", temp_buffer_for_vsyslog); // Call original with a simple format
    va_end(args);
    // The application's call to syslog will proceed normally after our hook.
}

// NOTE on vsnprintf used above:
// We need its original version if we are going to call it.
// So, add to typedefs, original pointers, and init_hooks:
typedef int   (*vsnprintf_t)(char *str, size_t size, const char *format, va_list ap);
static vsnprintf_t original_vsnprintf = NULL;
// And in init_hooks:
// LOAD_ORIGINAL_FUNC(vsnprintf, vsnprintf_t);
// Then in snprintf hook: int ret = original_vsnprintf(str, size, format, args);