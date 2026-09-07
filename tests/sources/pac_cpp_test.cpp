#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <typeinfo>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

class Animal {
public:
    virtual ~Animal() = default;
    virtual const char *speak() const = 0;
    virtual int legs() const = 0;
    virtual void feed(int amount) { printf("fed %d\n", amount); }
};

class Dog : public Animal {
    int energy;
public:
    Dog() : energy(100) {}
    const char *speak() const override { return "woof"; }
    int legs() const override { return 4; }
    void feed(int amount) override { energy += amount; printf("dog energy=%d\n", energy); }
};

class Snake : public Animal {
public:
    const char *speak() const override { return "hiss"; }
    int legs() const override { return 0; }
};

class Spider : public Animal {
public:
    const char *speak() const override { return "..."; }
    int legs() const override { return 8; }
};

class AnimalFactory {
public:
    virtual ~AnimalFactory() = default;
    virtual Animal *create(const char *type) = 0;
};

class DefaultFactory : public AnimalFactory {
public:
    Animal *create(const char *type) override {
        if (strcmp(type, "dog") == 0) return new Dog();
        if (strcmp(type, "snake") == 0) return new Snake();
        if (strcmp(type, "spider") == 0) return new Spider();
        return nullptr;
    }
};

typedef void (*EventHandler)(void *ctx, int event_id);
typedef int (*Comparator)(const void *, const void *);

struct Plugin {
    const char *name;
    int version;
    EventHandler on_event;
    Comparator sort_func;
    void (*cleanup)(Plugin *self);
};

void default_event(void *ctx, int event_id) {
    printf("event %d ctx=%p\n", event_id, ctx);
}

int default_compare(const void *a, const void *b) {
    return *(const int*)a - *(const int*)b;
}

void plugin_cleanup(Plugin *self) {
    printf("cleanup %s\n", self->name);
}

void dispatch_events(Plugin **plugins, int count) {
    for (int i = 0; i < count; i++) {
        if (plugins[i] && plugins[i]->on_event) {
            plugins[i]->on_event(plugins[i], i);
        }
        if (plugins[i] && plugins[i]->sort_func) {
            int arr[] = {3,1,2};
            qsort(arr, 3, sizeof(int), plugins[i]->sort_func);
        }
    }
}

void polymorphic_dispatch(Animal **animals, int count) {
    for (int i = 0; i < count; i++) {
        printf("%s says %s with %d legs\n",
               typeid(*animals[i]).name(), animals[i]->speak(), animals[i]->legs());
        animals[i]->feed(10);
    }
}

static jmp_buf cpp_recovery;

void cpp_signal_handler(int sig) {
    longjmp(cpp_recovery, sig);
}

void test_exception_flow() {
    try {
        throw std::runtime_error("test");
    } catch (const std::exception &e) {
        printf("caught: %s\n", e.what());
    }
}

void test_rtti_and_cast(Animal *a) {
    Dog *d = dynamic_cast<Dog*>(a);
    if (d) d->feed(100);
}

int main(int argc, char *argv[]) {
    DefaultFactory factory;
    Animal *animals[] = {
        factory.create("dog"),
        factory.create("snake"),
        factory.create("spider"),
    };
    polymorphic_dispatch(animals, 3);
    test_rtti_and_cast(animals[0]);

    Plugin p1 = {"audio", 1, default_event, default_compare, plugin_cleanup};
    Plugin p2 = {"video", 2, default_event, nullptr, plugin_cleanup};
    Plugin *plugins[] = {&p1, &p2};
    dispatch_events(plugins, 2);

    signal(SIGSEGV, cpp_signal_handler);
    if (setjmp(cpp_recovery) == 0) {
        test_exception_flow();
    }

    for (auto *a : animals) delete a;
    return 0;
}
