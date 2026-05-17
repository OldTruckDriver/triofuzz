#pragma once

#include <memory>
#include <type_traits>
#include <utility>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <typeinfo>

// C++14 compatibility layer for C++17 features

namespace triofuzz {

// nullopt_t definition (not just forward declaration)
struct nullopt_t {
    explicit constexpr nullopt_t(int) {}
};

// Simple optional implementation for C++14
template<typename T>
class optional {
private:
    alignas(T) unsigned char storage_[sizeof(T)];
    bool has_value_ = false;

public:
    optional() = default;

    optional(const nullopt_t&) : has_value_(false) {}

    optional(const T& value) {
        construct(value);
    }

    optional(T&& value) {
        construct(std::move(value));
    }

    optional(const optional& other) {
        if (other.has_value_) {
            construct(*other);
        }
    }

    optional(optional&& other) noexcept {
        if (other.has_value_) {
            construct(std::move(*other));
            other.reset();
        }
    }

    ~optional() {
        reset();
    }

    optional& operator=(const optional& other) {
        if (this != &other) {
            reset();
            if (other.has_value_) {
                construct(*other);
            }
        }
        return *this;
    }

    optional& operator=(optional&& other) noexcept {
        if (this != &other) {
            reset();
            if (other.has_value_) {
                construct(std::move(*other));
                other.reset();
            }
        }
        return *this;
    }

    optional& operator=(const T& value) {
        reset();
        construct(value);
        return *this;
    }

    optional& operator=(T&& value) {
        reset();
        construct(std::move(value));
        return *this;
    }

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    T& value() {
        if (!has_value_) {
            throw std::runtime_error("bad optional access");
        }
        return *reinterpret_cast<T*>(storage_);
    }

    const T& value() const {
        if (!has_value_) {
            throw std::runtime_error("bad optional access");
        }
        return *reinterpret_cast<const T*>(storage_);
    }

    T& operator*() { return value(); }
    const T& operator*() const { return value(); }

    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

    T value_or(const T& default_value) const {
        return has_value_ ? value() : default_value;
    }

    T value_or(T&& default_value) const {
        return has_value_ ? value() : std::move(default_value);
    }

    void reset() {
        if (has_value_) {
            reinterpret_cast<T*>(storage_)->~T();
            has_value_ = false;
        }
    }

    template<typename... Args>
    void emplace(Args&&... args) {
        reset();
        construct(std::forward<Args>(args)...);
    }

private:
    template<typename... Args>
    void construct(Args&&... args) {
        ::new (storage_) T(std::forward<Args>(args)...);
        has_value_ = true;
    }
};

// nullopt constant
static constexpr nullopt_t nullopt{0};

// bad_any_cast exception
class bad_any_cast : public std::bad_cast {
public:
    const char* what() const noexcept override {
        return "bad any_cast";
    }
};

// Simple any implementation for C++14
class any {
private:
    struct base_holder {
        virtual ~base_holder() = default;
        virtual std::unique_ptr<base_holder> clone() const = 0;
        virtual const std::type_info& type() const = 0;
        virtual void* get() = 0;
    };

    template<typename T>
    struct holder : base_holder {
        T value;

        holder(const T& v) : value(v) {}
        holder(T&& v) : value(std::move(v)) {}

        std::unique_ptr<base_holder> clone() const override {
            return std::make_unique<holder>(value);
        }

        const std::type_info& type() const override {
            return typeid(T);
        }

        void* get() override {
            return &value;
        }
    };

    std::unique_ptr<base_holder> content_;

public:
    any() = default;

    template<typename T>
    any(T&& value) : content_(std::make_unique<holder<typename std::decay<T>::type>>(std::forward<T>(value))) {}

    any(const any& other) : content_(other.content_ ? other.content_->clone() : nullptr) {}

    any(any&& other) noexcept : content_(std::move(other.content_)) {}

    any& operator=(const any& other) {
        if (this != &other) {
            content_ = other.content_ ? other.content_->clone() : nullptr;
        }
        return *this;
    }

    any& operator=(any&& other) noexcept {
        if (this != &other) {
            content_ = std::move(other.content_);
        }
        return *this;
    }

    template<typename T>
    any& operator=(T&& value) {
        content_ = std::make_unique<holder<typename std::decay<T>::type>>(std::forward<T>(value));
        return *this;
    }

    bool has_value() const { return content_ != nullptr; }

    const std::type_info& type() const {
        return content_ ? content_->type() : typeid(void);
    }

    void reset() { content_.reset(); }

    template<typename T>
    friend T* any_cast(any* a);

    template<typename T>
    friend const T* any_cast(const any* a);
};

template<typename T>
T* any_cast(any* a) {
    if (!a || !a->content_ || a->content_->type() != typeid(T)) {
        return nullptr;
    }
    return static_cast<T*>(a->content_->get());
}

template<typename T>
const T* any_cast(const any* a) {
    if (!a || !a->content_ || a->content_->type() != typeid(T)) {
        return nullptr;
    }
    return static_cast<const T*>(a->content_->get());
}

template<typename T>
T any_cast(const any& a) {
    using NonRef = typename std::remove_reference<T>::type;
    const NonRef* result = any_cast<NonRef>(&a);
    if (!result) {
        throw bad_any_cast();
    }
    return *result;
}

// Helper templates for variant implementation
namespace detail {
    template<size_t N, typename... Ts>
    struct nth_type_helper;

    // Base case - when index is 0
    template<typename First, typename... Rest>
    struct nth_type_helper<0, First, Rest...> {
        using type = First;
    };

    // Recursive case
    template<size_t N, typename First, typename... Rest>
    struct nth_type_helper<N, First, Rest...> {
        using type = typename nth_type_helper<N-1, Rest...>::type;
    };

    // Error case - ran out of types
    template<size_t N>
    struct nth_type_helper<N> {
        // This will cause a compile error if accessed
    };
}

// Simple variant implementation for common use cases
// Limited to up to 8 types for simplicity
template<typename... Types>
class variant {
private:
    static constexpr size_t data_size = std::max({sizeof(Types)...});
    static constexpr size_t data_align = std::max({alignof(Types)...});

    using storage_t = typename std::aligned_storage<data_size, data_align>::type;

    storage_t storage_;
    size_t index_ = 0;

    template<typename T, typename First, typename... Rest>
    struct find_index_impl {
        static constexpr size_t value = std::is_same<T, First>::value ? 0 : 1 + find_index_impl<T, Rest...>::value;
    };

    template<typename T, typename Last>
    struct find_index_impl<T, Last> {
        static constexpr size_t value = std::is_same<T, Last>::value ? 0 : size_t(-1);
    };

    template<typename T>
    static constexpr size_t find_index() {
        return find_index_impl<T, Types...>::value;
    }

    template<size_t N>
    using nth_type = typename detail::nth_type_helper<N, Types...>::type;

    struct destroyer {
        template<typename T>
        void operator()(T& t) const { t.~T(); }
    };

    template<size_t N = 0>
    typename std::enable_if<(N < sizeof...(Types)), void>::type
    destroy_impl() {
        if (index_ == N) {
            using T = nth_type<N>;
            reinterpret_cast<T*>(&storage_)->~T();
        } else {
            destroy_impl<N + 1>();
        }
    }

    template<size_t N = 0>
    typename std::enable_if<(N >= sizeof...(Types)), void>::type
    destroy_impl() {
        // End of recursion - do nothing
    }

public:
    variant() {
        using First = typename detail::nth_type_helper<0, Types...>::type;
        new (&storage_) First();
        index_ = 0;
    }

    template<typename T>
    variant(T&& value) {
        constexpr size_t idx = find_index<typename std::decay<T>::type>();
        static_assert(idx != size_t(-1), "Type not in variant");
        new (&storage_) typename std::decay<T>::type(std::forward<T>(value));
        index_ = idx;
    }

    variant(const variant& other) : index_(other.index_) {
        copy_construct(other);
    }

    variant(variant&& other) noexcept : index_(other.index_) {
        move_construct(std::move(other));
    }

    ~variant() {
        destroy_impl();
    }

    variant& operator=(const variant& other) {
        if (this != &other) {
            destroy_impl();
            index_ = other.index_;
            copy_construct(other);
        }
        return *this;
    }

    variant& operator=(variant&& other) noexcept {
        if (this != &other) {
            destroy_impl();
            index_ = other.index_;
            move_construct(std::move(other));
        }
        return *this;
    }

    template<typename T>
    variant& operator=(T&& value) {
        constexpr size_t idx = find_index<typename std::decay<T>::type>();
        static_assert(idx != size_t(-1), "Type not in variant");
        destroy_impl();
        new (&storage_) typename std::decay<T>::type(std::forward<T>(value));
        index_ = idx;
        return *this;
    }

    size_t index() const { return index_; }

    template<typename T>
    T* get_if() {
        constexpr size_t idx = find_index<T>();
        if (index_ == idx) {
            return reinterpret_cast<T*>(&storage_);
        }
        return nullptr;
    }

    template<typename T>
    const T* get_if() const {
        constexpr size_t idx = find_index<T>();
        if (index_ == idx) {
            return reinterpret_cast<const T*>(&storage_);
        }
        return nullptr;
    }

    template<typename T>
    T& get() {
        T* ptr = get_if<T>();
        if (!ptr) {
            throw std::runtime_error("bad variant access");
        }
        return *ptr;
    }

    template<typename T>
    const T& get() const {
        const T* ptr = get_if<T>();
        if (!ptr) {
            throw std::runtime_error("bad variant access");
        }
        return *ptr;
    }

private:
    template<size_t N = 0>
    typename std::enable_if<(N < sizeof...(Types)), void>::type
    copy_construct_impl(const variant& other) {
        if (other.index_ == N) {
            using T = nth_type<N>;
            new (&storage_) T(*reinterpret_cast<const T*>(&other.storage_));
        } else {
            copy_construct_impl<N + 1>(other);
        }
    }

    template<size_t N = 0>
    typename std::enable_if<(N >= sizeof...(Types)), void>::type
    copy_construct_impl(const variant&) {
        // End of recursion - do nothing
    }

    void copy_construct(const variant& other) {
        copy_construct_impl(other);
    }

    template<size_t N = 0>
    typename std::enable_if<(N < sizeof...(Types)), void>::type
    move_construct_impl(variant&& other) {
        if (other.index_ == N) {
            using T = nth_type<N>;
            new (&storage_) T(std::move(*reinterpret_cast<T*>(&other.storage_)));
        } else {
            move_construct_impl<N + 1>(std::move(other));
        }
    }

    template<size_t N = 0>
    typename std::enable_if<(N >= sizeof...(Types)), void>::type
    move_construct_impl(variant&&) {
        // End of recursion - do nothing
    }

    void move_construct(variant&& other) {
        move_construct_impl(std::move(other));
    }
};

// Helper for variant
template<typename T, typename... Types>
T* get_if(variant<Types...>* v) {
    return v ? v->template get_if<T>() : nullptr;
}

template<typename T, typename... Types>
const T* get_if(const variant<Types...>* v) {
    return v ? v->template get_if<T>() : nullptr;
}

template<typename T, typename... Types>
T& get(variant<Types...>& v) {
    return v.template get<T>();
}

template<typename T, typename... Types>
const T& get(const variant<Types...>& v) {
    return v.template get<T>();
}

// Simple shared_mutex implementation for C++14 (using regular mutex as fallback)
#if __cplusplus < 201703L
class shared_mutex {
private:
    mutable std::mutex mutex_;

public:
    void lock() {
        mutex_.lock();
    }

    void unlock() {
        mutex_.unlock();
    }

    bool try_lock() {
        return mutex_.try_lock();
    }

    // For C++14 compatibility, shared operations just use regular lock
    void lock_shared() {
        mutex_.lock();
    }

    void unlock_shared() {
        mutex_.unlock();
    }

    bool try_lock_shared() {
        return mutex_.try_lock();
    }
};

template<typename Mutex>
class shared_lock {
private:
    Mutex* mutex_;
    bool owns_;

public:
    explicit shared_lock(Mutex& m) : mutex_(&m), owns_(false) {
        mutex_->lock_shared();
        owns_ = true;
    }

    ~shared_lock() {
        if (owns_) {
            mutex_->unlock_shared();
        }
    }

    // Disable copy
    shared_lock(const shared_lock&) = delete;
    shared_lock& operator=(const shared_lock&) = delete;

    // Enable move
    shared_lock(shared_lock&& other) noexcept : mutex_(other.mutex_), owns_(other.owns_) {
        other.mutex_ = nullptr;
        other.owns_ = false;
    }

    shared_lock& operator=(shared_lock&& other) noexcept {
        if (this != &other) {
            if (owns_) {
                mutex_->unlock_shared();
            }
            mutex_ = other.mutex_;
            owns_ = other.owns_;
            other.mutex_ = nullptr;
            other.owns_ = false;
        }
        return *this;
    }

    void lock() {
        if (mutex_ && !owns_) {
            mutex_->lock_shared();
            owns_ = true;
        }
    }

    void unlock() {
        if (mutex_ && owns_) {
            mutex_->unlock_shared();
            owns_ = false;
        }
    }
};
#endif

// C++14 implementation of std::clamp
template<typename T>
constexpr const T& clamp(const T& v, const T& lo, const T& hi) {
    return (v < lo) ? lo : (hi < v) ? hi : v;
}

template<typename T, typename Compare>
constexpr const T& clamp(const T& v, const T& lo, const T& hi, Compare comp) {
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

} // namespace triofuzz

// For C++14 compatibility, create aliases in std namespace
// Note: These may conflict with standard library headers if included
#if __cplusplus < 201703L
namespace std {
    // Use template aliases to avoid conflicts
    template<typename T>
    using optional = triofuzz::optional<T>;

    using nullopt_t = triofuzz::nullopt_t;
    static constexpr triofuzz::nullopt_t nullopt{0};

    using any = triofuzz::any;
    using bad_any_cast = triofuzz::bad_any_cast;

    using triofuzz::any_cast;

    template<typename... Types>
    using variant = triofuzz::variant<Types...>;

    using triofuzz::get_if;
    using triofuzz::get;

    // Add clamp functions
    using triofuzz::clamp;
}
#endif