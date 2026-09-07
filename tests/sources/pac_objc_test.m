#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

typedef void (^CompletionBlock)(NSError *error, id result);
typedef id (*IMPFunction)(id, SEL, ...);

@protocol PluginProtocol <NSObject>
- (BOOL)initialize:(NSDictionary *)config;
- (id)processInput:(id)input;
- (void)cleanup;
@optional
- (void)handleError:(NSError *)error;
@end

@interface MessageDispatcher : NSObject
@property (nonatomic, copy) CompletionBlock onComplete;
@property (nonatomic, strong) NSMutableDictionary *handlers;
- (void)registerHandler:(SEL)selector forMessage:(NSString *)name;
- (void)dispatch:(NSString *)message withPayload:(id)payload;
@end

@implementation MessageDispatcher

- (instancetype)init {
    self = [super init];
    if (self) {
        _handlers = [NSMutableDictionary new];
    }
    return self;
}

- (void)registerHandler:(SEL)selector forMessage:(NSString *)name {
    self.handlers[name] = NSStringFromSelector(selector);
}

- (void)dispatch:(NSString *)message withPayload:(id)payload {
    NSString *selName = self.handlers[message];
    if (selName) {
        SEL sel = NSSelectorFromString(selName);
        if ([self respondsToSelector:sel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            [self performSelector:sel withObject:payload];
#pragma clang diagnostic pop
        }
    }
    if (self.onComplete) {
        self.onComplete(nil, payload);
    }
}

- (void)handleEcho:(id)payload {
    NSLog(@"Echo: %@", payload);
}

- (void)handleTransform:(id)payload {
    NSLog(@"Transform: %@", [payload uppercaseString]);
}

@end

@interface DynamicPlugin : NSObject <PluginProtocol>
@property (nonatomic, strong) NSDictionary *config;
@property (nonatomic, copy) CompletionBlock callback;
@end

@implementation DynamicPlugin

- (BOOL)initialize:(NSDictionary *)config {
    self.config = config;
    return YES;
}

- (id)processInput:(id)input {
    if (self.callback) {
        self.callback(nil, input);
    }
    return input;
}

- (void)cleanup {
    self.config = nil;
    self.callback = nil;
}

- (void)handleError:(NSError *)error {
    NSLog(@"Plugin error: %@", error);
}

@end

@interface RuntimeSwizzler : NSObject
+ (void)swizzleClass:(Class)cls original:(SEL)orig replacement:(SEL)repl;
+ (IMP)lookupIMP:(Class)cls selector:(SEL)sel;
@end

@implementation RuntimeSwizzler

+ (void)swizzleClass:(Class)cls original:(SEL)orig replacement:(SEL)repl {
    Method origMethod = class_getInstanceMethod(cls, orig);
    Method replMethod = class_getInstanceMethod(cls, repl);
    if (origMethod && replMethod) {
        method_exchangeImplementations(origMethod, replMethod);
    }
}

+ (IMP)lookupIMP:(Class)cls selector:(SEL)sel {
    return class_getMethodImplementation(cls, sel);
}

@end

static jmp_buf objc_recovery;

void objc_signal_handler(int sig) {
    longjmp(objc_recovery, sig);
}

void test_exception_handling(void) {
    @try {
        @autoreleasepool {
            NSArray *arr = @[@"a", @"b"];
            [arr objectAtIndex:10];
        }
    } @catch (NSException *exception) {
        NSLog(@"Caught: %@", exception.name);
    } @finally {
        NSLog(@"Finally block");
    }
}

void test_blocks_and_closures(void) {
    NSMutableArray *blocks = [NSMutableArray new];
    for (int i = 0; i < 5; i++) {
        void (^block)(void) = ^{
            NSLog(@"Block %d", i);
        };
        [blocks addObject:[block copy]];
    }
    for (void (^block)(void) in blocks) {
        block();
    }
}

void test_kvo_and_notifications(void) {
    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    id observer = [center addObserverForName:@"TestNotification"
                                      object:nil
                                       queue:nil
                                  usingBlock:^(NSNotification *note) {
        NSLog(@"Received: %@", note.userInfo);
    }];
    [center postNotificationName:@"TestNotification"
                          object:nil
                        userInfo:@{@"key": @"value"}];
    [center removeObserver:observer];
}

void test_dynamic_loading(void) {
    void *handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
    if (handle) {
        void *sym = dlsym(handle, "getenv");
        if (sym) {
            typedef char *(*getenv_fn)(const char *);
            getenv_fn fn = (getenv_fn)sym;
            char *home = fn("HOME");
            NSLog(@"HOME=%s", home ? home : "(null)");
        }
        dlclose(handle);
    }
}

void test_forked_objc(void) {
    pid_t pid = fork();
    if (pid == 0) {
        NSLog(@"Child ObjC process");
        _exit(0);
    }
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        MessageDispatcher *dispatcher = [MessageDispatcher new];
        [dispatcher registerHandler:@selector(handleEcho:) forMessage:@"echo"];
        [dispatcher registerHandler:@selector(handleTransform:) forMessage:@"transform"];

        dispatcher.onComplete = ^(NSError *error, id result) {
            NSLog(@"Complete: %@", result);
        };

        [dispatcher dispatch:@"echo" withPayload:@"hello"];
        [dispatcher dispatch:@"transform" withPayload:@"world"];

        DynamicPlugin *plugin = [DynamicPlugin new];
        [plugin initialize:@{@"mode": @"test"}];
        plugin.callback = ^(NSError *error, id result) {
            NSLog(@"Plugin callback: %@", result);
        };
        [plugin processInput:@"data"];
        [plugin cleanup];

        IMP imp = [RuntimeSwizzler lookupIMP:[NSString class]
                                    selector:@selector(length)];
        NSLog(@"IMP for -[NSString length]: %p", imp);

        test_exception_handling();
        test_blocks_and_closures();
        test_kvo_and_notifications();
        test_dynamic_loading();
        test_forked_objc();

        signal(SIGSEGV, objc_signal_handler);
        if (setjmp(objc_recovery) == 0) {
            NSLog(@"Signal recovery test OK");
        }
    }
    return 0;
}
